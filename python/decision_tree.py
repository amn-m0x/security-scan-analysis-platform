"""Inference using the locally trained educational decision tree."""

from pathlib import Path

import joblib
import sklearn

from tree_features import FEATURE_NAMES, extract_features


ROOT = Path(__file__).resolve().parent.parent


class DecisionTreeDetector:
    def __init__(self):
        path = ROOT / "results/decision_tree.joblib"

        if not path.is_file():
            raise ValueError(
                "Model missing. Run python python/train_tree.py first."
            )

        # Load only the model produced locally by train_tree.py.
        bundle = joblib.load(path)

        if bundle["feature_names"] != FEATURE_NAMES:
            raise ValueError("Model feature schema mismatch.")
        if bundle["sklearn_version"] != sklearn.__version__:
            raise ValueError(
                "scikit-learn version changed. Retrain the model."
            )

        self.model = bundle["model"]

    def evaluate(self, findings):
        features = extract_features(findings)
        prediction = self.model.predict([features])[0]

        return {
            "detected": bool(prediction),
            "model": "DecisionTreeClassifier",
            "training_scope": "synthetic_educational",
            "features": dict(zip(FEATURE_NAMES, features)),
        }

