"""Convert parsed Nmap data into a normalized single-target scan."""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def normalize(data, target):
    if not isinstance(data, dict) or not isinstance(data.get("hosts"), list):
        raise ValueError("Input must contain a hosts list.")

    matching_hosts = []
    for host in data["hosts"]:
        if not isinstance(host, dict):
            raise ValueError("Each host must be an object.")
        if host.get("address") == target:
            matching_hosts.append(host)

    if not matching_hosts:
        raise ValueError(f"Target not found in input: {target}")

    findings = []

    for host in matching_hosts:
        ports = host.get("ports")
        if not isinstance(ports, list):
            raise ValueError("Host ports must be a list.")

        for port in ports:
            if not isinstance(port, dict):
                raise ValueError("Each port must be an object.")

            state = port.get("state")
            if not isinstance(state, str) or not state:
                raise ValueError("Port state is missing.")

            if state != "open":
                continue

            number = port.get("port")
            if type(number) is not int or not 0 <= number <= 65535:
                raise ValueError("Invalid port number.")

            service = port.get("service") or ""
            product = port.get("product") or ""
            version = port.get("version") or ""

            findings.append({
                "target": target,
                "source": "nmap",
                "type": "service",
                "port": number,
                "protocol": port.get("protocol") or "unknown",
                "state": state,
                "service": service,
                "product": product,
                "version": version,
                "severity": "info",
                "description": (
                    f"Open port {number}: {service} {product} {version}"
                ).strip(),
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
        description="Normalize Nmap parser output for one target."
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
        parser.exit(1, f"Normalization failed: {error}\n")

    print(f"Target: {scan['target']}")
    print(f"Open-port findings: {len(scan['findings'])}")
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
