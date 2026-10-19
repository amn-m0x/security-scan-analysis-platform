"""Concurrent, fixed-target lab scan. Never invokes a shell or sudo."""
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
TARGET = "192.0.2.2"


def command(args, log, timeout=360):
    with log.open("wb") as output:
        result = subprocess.run([str(a) for a in args], cwd=ROOT,
                                stdout=output, stderr=subprocess.STDOUT,
                                timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}); see {log}")


def run():
    for executable in ("nmap", "masscan", "perl"):
        if not shutil.which(executable):
            raise RuntimeError(f"Missing executable: {executable}")
    nikto = Path.home() / "tools/nikto/program/nikto.pl"
    for path in (nikto, ROOT / "build/nmap_parser", ROOT / "results/decision_tree.joblib"):
        if not path.is_file():
            raise RuntimeError(f"Missing prerequisite: {path}")
    # An explicit lab interface and reachable lab HTTP service are required.
    if not Path("/sys/class/net/mc-host").exists():
        raise RuntimeError("Lab interface missing. Run bash setup_lab.sh first.")
    mac_file = ROOT / "results/lab-target-mac.txt"
    mac = mac_file.read_text().strip()
    import re
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        raise RuntimeError("Invalid lab MAC; run setup_lab.sh again.")
    with urlopen(f"http://{TARGET}:8000", timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("Lab HTTP server is not ready.")
    folder = Path(tempfile.mkdtemp(prefix="live-", dir=ROOT / "results"))
    specs = {
        "nmap": ["nmap", "-sT", "-sV", "-Pn", "-p8000", "-oX", folder / "nmap.xml", TARGET],
        "masscan": ["masscan", TARGET, "-p8000", "-e", "mc-host", "--router-mac", mac,
                    "--rate", "10", "--wait", "5", "-oJ", folder / "masscan.json"],
        "nikto": ["perl", nikto, "-h", f"http://{TARGET}:8000", "-Format", "json",
                  "-o", folder / "nikto.json"],
    }
    def scan(name, args):
        start = time.time()
        try:
            command(args, folder / f"{name}.log")
            return {"status": "completed", "started": start, "finished": time.time()}
        except Exception as error:
            return {"status": "failed", "started": start, "finished": time.time(), "error": str(error)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        tasks = {name: pool.submit(scan, name, args) for name, args in specs.items()}
        statuses = {name: task.result() for name, task in tasks.items()}
    (folder / "scanner_status.json").write_text(json.dumps(statuses, indent=2))
    if any(item["status"] != "completed" for item in statuses.values()):
        raise RuntimeError(f"One or more scanners failed. No complete assessment produced. See {folder}/scanner_status.json")
    with (folder / "nmap_parsed.json").open("wb") as output:
        subprocess.run([str(ROOT / "build/nmap_parser"), str(folder / "nmap.xml")],
                       stdout=output, check=True, timeout=30)
    python = sys.executable
    inputs = []
    for name in specs:
        raw = folder / ("nmap_parsed.json" if name == "nmap" else f"{name}.json")
        normalized = folder / f"{name}_scan.json"
        command([python, ROOT / f"python/normalize_{name}.py", raw, "--target", TARGET,
                 "--output", normalized], folder / f"{name}-normalize.log", 30)
        inputs.append(normalized)
    combined = folder / "combined_scan.json"
    command([python, ROOT / "python/merge_scans.py", *inputs, "--target", TARGET,
             "--output", combined], folder / "merge.log", 30)
    with combined.open("rb") as source:
        result = subprocess.run([python, ROOT / "python/api_bridge.py"], cwd=ROOT,
                                stdin=source, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    report = json.loads(result.stdout)
    report["live_scan"] = {"directory": str(folder.relative_to(ROOT)), "scanners": statuses}
    (folder / "incident.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    try:
        print(json.dumps(run()))
    except Exception as error:
        print(f"Live scan failed: {error}", file=sys.stderr)
        sys.exit(1)
