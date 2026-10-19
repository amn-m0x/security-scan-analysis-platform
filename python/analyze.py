"""Read a normalized scan and save its rule-based assessment."""

import argparse
import json
from pathlib import Path

from expert_system import ExpertSystem
from decision_tree import DecisionTreeDetector


ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(
        description="Analyze normalized security scan findings."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--rules",
        type=Path,
        default=ROOT / "rules" / "rules.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "incident.json",
    )
    args = parser.parse_args()

    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError("Input and output must be different files.")

        scan = json.loads(args.input.read_text(encoding="utf-8"))

        if not isinstance(scan, dict):
            raise ValueError("Scan must be a JSON object.")

        for field in ("scan_id", "timestamp", "target"):
            if not isinstance(scan.get(field), str) or not scan[field].strip():
                raise ValueError(f"Missing or invalid field: {field}")

        findings = scan.get("findings")
        if not isinstance(findings, list):
            raise ValueError("findings must be a list.")
        if not all(isinstance(item, dict) for item in findings):
            raise ValueError("Each finding must be a JSON object.")

        engine = ExpertSystem(args.rules)
        incident = engine.evaluate(findings)
        tree_result = DecisionTreeDetector().evaluate(findings)
        tree_result["agrees_with_rules"] = (
            tree_result["detected"] == incident["detected"]
        )

        result = {
            "scan_id": scan["scan_id"],
            "timestamp": scan["timestamp"],
            "target": scan["target"],
            "findings": findings,
            "incident": incident,
            "decision_tree": tree_result,
        }

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Analysis failed: {error}\n")

    print(f"Target: {scan['target']}")
    print(f"Detected: {incident['detected']}")
    print(f"Risk score: {incident['risk_score']}")
    print(f"Category: {incident['category']}")
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
