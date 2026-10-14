"""Evaluate the rule engine against manually labelled synthetic cases."""

import json
from pathlib import Path

from expert_system import ExpertSystem


ROOT = Path(__file__).resolve().parent.parent


def main():
    dataset_path = ROOT / "data/samples/evaluation_cases.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    cases = dataset["cases"]

    if not isinstance(cases, list) or not cases:
        raise ValueError("A non-empty cases list is required.")

    engine = ExpertSystem(ROOT / "rules/rules.yaml")
    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    details = []
    identifiers = set()

    for case in cases:
        identifier = case["id"]
        if identifier in identifiers:
            raise ValueError("Duplicate case ID: " + identifier)
        identifiers.add(identifier)

        actual = case["actual"]
        if type(actual) is not bool:
            raise ValueError("actual must be a boolean.")

        findings = case["findings"]
        if not isinstance(findings, list):
            raise ValueError("findings must be a list.")
        if not all(isinstance(item, dict) for item in findings):
            raise ValueError("Each finding must be an object.")

        incident = engine.evaluate(findings)
        predicted = incident.detected if hasattr(incident, "detected") else incident["detected"]

        if predicted and actual:
            outcome = "TP"
        elif predicted and not actual:
            outcome = "FP"
        elif not predicted and actual:
            outcome = "FN"
        else:
            outcome = "TN"

        counts[outcome] += 1
        details.append({
            "id": identifier,
            "actual": actual,
            "predicted": predicted,
            "outcome": outcome,
            "reason": case["reason"],
        })
        print(identifier, "=>", outcome)

    tp = counts["TP"]
    fp = counts["FP"]
    fn = counts["FN"]
    tn = counts["TN"]

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0

    report = {
        "dataset_type": dataset["dataset_type"],
        "label_definition": dataset["label_definition"],
        "sample_count": len(cases),
        "confusion_matrix": counts,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": (tp + tn) / len(cases),
        "zero_division_policy": "Return 0.0 for undefined metrics",
        "cases": details,
    }

    output = ROOT / "results/evaluation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print("Confusion matrix:", counts)
    print("Precision:", round(precision, 4))
    print("Recall:", round(recall, 4))
    print("F1:", round(f1, 4))
    print("Saved:", output)


if __name__ == "__main__":
    main()
