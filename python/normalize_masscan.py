"""Normalize a Masscan JSON array for one selected target."""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def normalize(records, target):
    if not isinstance(records, list):
        raise ValueError("Expected a JSON array of Masscan records.")

    findings = []
    seen = set()

    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each record must be an object.")

        address = record.get("ip")
        ports = record.get("ports")

        if not isinstance(address, str) or not address:
            raise ValueError("Record has no valid IP address.")
        if not isinstance(ports, list):
            raise ValueError("Record ports must be a list.")

        for port in ports:
            if not isinstance(port, dict):
                raise ValueError("Each port must be an object.")

            number = port.get("port")
            protocol = port.get("proto")
            state = port.get("status")

            if type(number) is not int or not 0 <= number <= 65535:
                raise ValueError("Invalid port number.")
            if not isinstance(protocol, str) or not protocol:
                raise ValueError("Missing port protocol.")
            if not isinstance(state, str) or not state:
                raise ValueError("Missing port status.")

            if address != target or state != "open":
                continue

            key = (address, protocol, number)
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "target": address,
                "source": "masscan",
                "type": "port",
                "port": number,
                "protocol": protocol,
                "state": state,
                "service": None,
                "product": None,
                "version": None,
                "severity": "info",
                "description": f"Open {protocol} port {number}",
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
        description="Normalize Masscan JSON for one target."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError("Input and output must be different files.")

        records = json.loads(args.input.read_text(encoding="utf-8"))
        scan = normalize(records, args.target)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(scan, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, TypeError) as error:
        parser.exit(1, f"Normalization failed: {error}\n")

    print("Target:", scan["target"])
    print("Open-port findings:", len(scan["findings"]))
    print("Saved:", args.output)


if __name__ == "__main__":
    main()
