"""Train and evaluate an educational decision tree on synthetic scenarios."""

import hashlib
import json
from pathlib import Path

import joblib
import sklearn
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.tree import DecisionTreeClassifier, export_text

from tree_features import FEATURE_NAMES, extract_features


ROOT = Path(__file__).resolve().parent.parent


def main():
    dataset_path = ROOT / "data/samples/tree_dataset.json"
    raw = dataset_path.read_bytes()
    dataset = json.loads(raw)
    cases = dataset["cases"]

    identifiers = set()
    for case in cases:
        if case["id"] in identifiers:
            raise ValueError("Duplicate scenario ID.")
        identifiers.add(case["id"])

        if case["split"] not in ("train", "test"):
            raise ValueError("Invalid split.")
        if type(case["actual"]) is not bool:
            raise ValueError("Labels must be boolean.")

    train = [case for case in cases if case["split"] == "train"]
    test = [case for case in cases if case["split"] == "test"]

    if not train or not test:
        raise ValueError("Both training and test scenarios are required.")

    x_train = [extract_features(case["findings"]) for case in train]
    y_train = [int(case["actual"]) for case in train]
    x_test = [extract_features(case["findings"]) for case in test]
    y_test = [int(case["actual"]) for case in test]

    if set(y_train) != {0, 1}:
        raise ValueError("Training data must contain both classes.")

    model = DecisionTreeClassifier(
        max_depth=4,
        random_state=42,
    )
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    details = []
    for case, prediction in zip(test, predictions):
        predicted = bool(prediction)
        details.append({
            "id": case["id"],
            "actual": case["actual"],
            "predicted": predicted,
        })
        print(
            case["id"],
            "| actual:", case["actual"],
            "| predicted:", predicted,
        )

    report = {
        "dataset_type": dataset["dataset_type"],
        "limitations": (
            "Tiny synthetic demonstration with related scenario families; "
            "not an estimate of real-world detection performance."
        ),
        "dataset_sha256": hashlib.sha256(raw).hexdigest(),
        "sklearn_version": sklearn.__version__,
        "train_ids": [case["id"] for case in train],
        "test_ids": [case["id"] for case in test],
        "feature_names": FEATURE_NAMES,
        "parameters": {"max_depth": 4, "random_state": 42},
        "confusion_matrix": {
            "TP": int(tp), "FP": int(fp),
            "FN": int(fn), "TN": int(tn),
        },
        "precision": float(precision_score(
            y_test, predictions, zero_division=0
        )),
        "recall": float(recall_score(
            y_test, predictions, zero_division=0
        )),
        "f1": float(f1_score(
            y_test, predictions, zero_division=0
        )),
        "cases": details,
    }

    output = ROOT / "results"
    output.mkdir(exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "feature_names": FEATURE_NAMES,
            "sklearn_version": sklearn.__version__,
        },
        output / "decision_tree.joblib",
    )

    tree_text = export_text(model, feature_names=FEATURE_NAMES)
    (output / "decision_tree.txt").write_text(
        tree_text, encoding="utf-8"
    )
    (output / "tree_evaluation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print("Training scenarios:", len(train))
    print("Test scenarios:", len(test))
    print("Confusion matrix:", report["confusion_matrix"])
    print("Precision:", round(report["precision"], 4))
    print("Recall:", round(report["recall"], 4))
    print("F1:", round(report["f1"], 4))
    print("Saved model: results/decision_tree.joblib")
    print("Saved tree: results/decision_tree.txt")


if __name__ == "__main__":
    main()

