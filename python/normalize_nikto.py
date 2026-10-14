"""Normalize a single-target Nikto JSON report."""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def normalize(data, target):
    if isinstance(data, list):
        if not all(isinstance(report, dict) for report in data):
            raise ValueError("Each report must be an object.")

        matching = [
            report for report in data
            if target in (report.get("ip"), report.get("host"))
        ]

        if len(matching) != 1:
            raise ValueError("Expected exactly one matching report.")

        data = matching[0]

    if not isinstance(data, dict):
        raise ValueError("Expected one JSON report object.")

    identities = [data.get("ip"), data.get("host")]
    if target not in identities:
        raise ValueError("Target does not match the report host or IP.")

    raw_port = data.get("port")
    if isinstance(raw_port, bool) or not isinstance(raw_port, (str, int)):
        raise ValueError("Missing or invalid port.")
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise ValueError("Port is out of range.")

    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("vulnerabilities must be a list.")

    findings = []

    for item in vulnerabilities:
        if not isinstance(item, dict):
            raise ValueError("Each vulnerability must be an object.")

        message = item.get("msg")
        if not isinstance(message, str) or not message.strip():
            raise ValueError("Finding has no valid msg field.")

        findings.append({
            "target": target,
            "source": "nikto",
            "type": "vulnerability",
            "port": port,
            "protocol": "tcp",
            "state": "reported",
            "service": None,
            "product": None,
            "version": None,
            "severity": "info",
            "description": message,
            "url": item.get("url"),
            "method": item.get("method"),
            "scanner_id": item.get("id"),
            "cwe": None,
            "cve": None,
        })

    return {
        "scan_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Normalize a single-target Nikto report."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError("Input and output must be different files.")

        data = json.loads(args.input.read_text(encoding="utf-8"))
        scan = normalize(data, args.target)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(scan, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, TypeError) as error:
        parser.exit(1, "Normalization failed: " + str(error) + "\n")

    print("Target:", scan["target"])
    print("Nikto findings:", len(scan["findings"]))
    print("Saved:", args.output)


if __name__ == "__main__":
    main()
