"""Validate the structure and values of security rules."""

import math
import sys
from pathlib import Path

import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


def is_text(value):
    return isinstance(value, str) and bool(value.strip())


def is_score(value):
    return (
        type(value) in (int, float)
        and math.isfinite(value)
        and 0 <= value <= 10
    )


def validate(path):
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(config, dict), "Root must be an object.")
    require(is_score(config.get("threshold")), "Invalid threshold.")

    rules = config.get("rules")
    require(isinstance(rules, list) and len(rules) > 0,
            "rules must be a non-empty list.")

    names = set()

    for rule in rules:
        require(isinstance(rule, dict), "Each rule must be an object.")

        name = rule.get("name")
        require(is_text(name), "Rule name is missing.")
        require(name not in names, "Duplicate rule name: " + name)
        names.add(name)

        require(is_text(rule.get("category")),
                "Invalid category: " + name)
        require(is_score(rule.get("risk_score")),
                "Invalid risk score: " + name)

        conditions = rule.get("conditions")
        require(isinstance(conditions, list) and len(conditions) > 0,
                "Missing conditions: " + name)

        for condition in conditions:
            require(isinstance(condition, dict),
                    "Condition must be an object: " + name)
            require(is_text(condition.get("field")),
                    "Invalid condition field: " + name)

            operator = condition.get("operator")
            require(isinstance(operator, str),
                    "Invalid operator type: " + name)
            require(operator in ("eq", "in", "gte", "contains"),
                    "Unsupported operator: " + name)
            require("value" in condition,
                    "Missing condition value: " + name)

            value = condition["value"]
            require(value is not None, "Null condition value: " + name)

            if operator == "contains":
                require(is_text(value),
                        "contains requires non-empty text: " + name)
            elif operator == "in":
                require(isinstance(value, list) and len(value) > 0,
                        "in requires a non-empty list: " + name)
            elif operator == "gte":
                require(
                    type(value) in (int, float) and math.isfinite(value),
                    "gte requires a finite number: " + name,
                )

        recommendations = rule.get("recommendations", [])
        require(isinstance(recommendations, list),
                "Recommendations must be a list: " + name)
        require(all(is_text(item) for item in recommendations),
                "Invalid recommendation: " + name)

    return len(rules)


def main():
    if len(sys.argv) != 2:
        print("Usage: validate_rules.py RULES_FILE", file=sys.stderr)
        return 2

    try:
        count = validate(Path(sys.argv[1]))
    except (OSError, ValueError, TypeError, yaml.YAMLError) as error:
        print("INVALID:", error, file=sys.stderr)
        return 1

    print("VALID rules:", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
