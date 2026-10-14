"""Evaluate normalized security findings against YAML rules."""

from pathlib import Path
import yaml


class ExpertSystem:
    def __init__(self, rules_path):
        text = Path(rules_path).read_text(encoding="utf-8")
        config = yaml.safe_load(text)

        self.threshold = float(config["threshold"])
        self.rules = config["rules"]

        allowed = {"eq", "in", "gte", "contains"}
        for rule in self.rules:
            if not rule.get("conditions"):
                raise ValueError(
                    f"Rule has no conditions: {rule['name']}"
                )
            for condition in rule["conditions"]:
                if condition["operator"] not in allowed:
                    raise ValueError(
                        f"Unsupported operator: {condition['operator']}"
                    )

    @staticmethod
    def check_condition(finding, condition):
        actual = finding.get(condition["field"])
        expected = condition["value"]
        operator = condition["operator"]

        if actual is None:
            return False

        if operator == "eq":
            return actual == expected

        if operator == "in":
            return actual in expected

        if operator == "contains":
            return str(expected).casefold() in str(actual).casefold()

        if operator == "gte":
            try:
                return float(actual) >= float(expected)
            except (TypeError, ValueError):
                return False

        return False

    def evaluate(self, findings):
        triggered = []
        categories = set()
        recommendations = set()
        risk_score = 0.0

        for rule in self.rules:
            matching = [
                finding
                for finding in findings
                if all(
                    self.check_condition(finding, condition)
                    for condition in rule["conditions"]
                )
            ]

            if not matching:
                continue

            score = float(rule["risk_score"])
            risk_score = max(risk_score, score)
            categories.add(rule["category"])
            recommendations.update(rule.get("recommendations", []))

            triggered.append({
                "rule": rule["name"],
                "risk_score": score,
                "findings": matching,
            })

        return {
            "detected": risk_score >= self.threshold,
            "risk_score": risk_score,
            "category": ", ".join(sorted(categories)) or "none",
            "recommendations": sorted(recommendations),
            "triggering_findings": triggered,
        }
