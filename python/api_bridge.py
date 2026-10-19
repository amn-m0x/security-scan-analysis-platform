"""Read one normalized scan from stdin and write its assessment."""

import json
import sys
from pathlib import Path

import yaml

from expert_system import ExpertSystem
from decision_tree import DecisionTreeDetector


ROOT = Path(__file__).resolve().parent.parent


def main():
    try:
        scan = json.load(sys.stdin)

        if not isinstance(scan, dict):
            raise ValueError("Request must be a JSON object.")

        for field in ("scan_id", "timestamp", "target"):
            value = scan.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Missing or invalid field: " + field)

        findings = scan.get("findings")
        if not isinstance(findings, list):
            raise ValueError("findings must be a list.")

        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("Each finding must be an object.")
            if finding.get("target", scan["target"]) != scan["target"]:
                raise ValueError("Finding target does not match scan target.")

    except (ValueError, TypeError) as error:
        print("Invalid request:", error, file=sys.stderr)
        return 2

    try:
        engine = ExpertSystem(ROOT / "rules" / "rules.yaml")
        incident = engine.evaluate(findings)
        tree_result = DecisionTreeDetector().evaluate(findings)
        tree_result["agrees_with_rules"] = (
            tree_result["detected"] == incident["detected"]
        )
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as error:
        print("Engine failed:", error, file=sys.stderr)
        return 1

    result = dict(scan)
    result["incident"] = incident
    result["decision_tree"] = tree_result

    json.dump(result, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

