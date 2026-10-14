"""Merge normalized scan findings for a single target."""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def merge_scans(paths, target):
    findings = []
    inputs = []

    for path in paths:
        scan = json.loads(path.read_text(encoding="utf-8"))

        if not isinstance(scan, dict):
            raise ValueError("Each scan must be a JSON object.")
        if scan.get("target") != target:
            raise ValueError("Target mismatch in " + str(path))

        items = scan.get("findings")
        if not isinstance(items, list):
            raise ValueError("Missing findings list in " + str(path))

        for finding in items:
            if not isinstance(finding, dict):
                raise ValueError("Each finding must be an object.")
            if finding.get("target") != target:
                raise ValueError("Finding target mismatch.")
            if finding.get("source") not in {"nmap", "masscan", "nikto"}:
                raise ValueError("Unknown or missing finding source.")

            findings.append(dict(finding))

        inputs.append({
            "file": str(path),
            "scan_id": scan.get("scan_id"),
            "timestamp": scan.get("timestamp"),
            "finding_count": len(items),
        })

    return {
        "scan_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "inputs": inputs,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Merge normalized scans for one target."
    )
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        resolved = [path.resolve() for path in args.inputs]
        if len(resolved) != len(set(resolved)):
            raise ValueError("The same input file was supplied twice.")
        if args.output.resolve() in resolved:
            raise ValueError("Output must not overwrite an input file.")

        merged = merge_scans(args.inputs, args.target)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(merged, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, TypeError) as error:
        parser.exit(1, "Merge failed: " + str(error) + "\n")

    print("Target:", merged["target"])
    print("Input reports:", len(merged["inputs"]))
    print("Total findings:", len(merged["findings"]))
    print("Saved:", args.output)


if __name__ == "__main__":
    main()
