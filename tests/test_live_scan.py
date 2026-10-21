"""Pipeline contract checks; real goroutine/process behavior is tested in Go."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location("live_scan", Path(__file__).parents[1] / "python/live_scan.py")
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class LiveScanTests(unittest.TestCase):
    def exercise(self, fail=False, malformed=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "results").mkdir()
            (root / "results/lab-target-mac.txt").write_text("aa:bb:cc:dd:ee:ff")
            def command(args, log, timeout=360):
                log.write_text("simulated")
                if str(args[0]).endswith("build/scan_runner"):
                    self.assertEqual(args[1], "--run-dir")
                    statuses = {name: {"status": "completed", "started": 1, "finished": 2}
                                for name in ("nmap", "masscan", "nikto")}
                    if fail: statuses["masscan"]["status"] = "failed"
                    if malformed: del statuses["nikto"]
                    (log.parent / "scanner_status.json").write_text(json.dumps(statuses))
                    if fail: raise RuntimeError("collector failed")
                if any(str(arg).endswith("merge_scans.py") for arg in args):
                    (log.parent / "combined_scan.json").write_text("{}")
            response = MagicMock()
            response.__enter__.return_value.status = 200
            fake_report = {"target": "192.0.2.2", "findings": [], "incident": {"detected": False}}
            with patch.object(live, "ROOT", root), patch.object(live.shutil, "which", return_value="tool"), patch.object(Path, "is_file", return_value=True), patch.object(Path, "exists", return_value=True), patch.object(live, "urlopen", return_value=response), patch.object(live, "command", side_effect=command), patch.object(live.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(fake_report).encode(), b"")) as sub:
                if fail or malformed:
                    with self.assertRaises(RuntimeError): live.run()
                    sub.assert_not_called()
                else:
                    report = live.run()
                    self.assertEqual(len(report["live_scan"]["scanners"]), 3)
            folder, = (root / "results").glob("live-*")
            self.assertEqual((folder / "incident.json").exists(), not (fail or malformed))

    def test_collector_success(self): self.exercise()
    def test_collector_failure_stops_analysis(self): self.exercise(fail=True)
    def test_incomplete_status_stops_analysis(self): self.exercise(malformed=True)


if __name__ == "__main__": unittest.main()
