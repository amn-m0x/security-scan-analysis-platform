"""Check a saved live report without running scanners or changing project data."""
import json
import math
from pathlib import Path
import sys


def check(report):
    if report.get("target") != "192.0.2.2":
        raise ValueError("Unexpected lab target")
    statuses = report["live_scan"]["scanners"]
    if set(statuses) != {"nmap", "masscan", "nikto"}:
        raise ValueError("Missing scanner status")
    for name, item in statuses.items():
        if item["status"] != "completed":
            raise ValueError(f"{name} did not complete")
        start, end = item["started"], item["finished"]
        if not all(type(t) in (int, float) and math.isfinite(t) for t in (start, end)) or end < start:
            raise ValueError("Invalid scanner timestamps")
        print(f"{name}: completed, {end-start:.2f} seconds")
    overlap = max(s["started"] for s in statuses.values()) < min(s["finished"] for s in statuses.values())
    print("Scanner intervals overlap:", overlap)
    if not overlap:
        raise ValueError("This run does not demonstrate overlapping scanner intervals")
    if not isinstance(report.get("findings"), list):
        raise ValueError("Missing normalized findings")
    if type(report["incident"]["detected"]) is not bool or type(report["decision_tree"]["detected"]) is not bool:
        raise ValueError("Missing rules/tree assessments")
    print("Findings:", len(report["findings"]))
    print("Rule alert:", report["incident"]["detected"])
    print("Tree alert:", report["decision_tree"]["detected"])
    print("PASS: Go-based live pipeline completed")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2: raise ValueError("Usage: verify_live_report.py REPORT.json")
        check(json.loads(Path(sys.argv[1]).read_text()))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("FAIL:", error, file=sys.stderr)
        sys.exit(1)
