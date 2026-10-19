"""Create explicitly labelled synthetic scenarios for a decision-tree demo."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


SCENARIOS = [
    {
        "id": "approved-ssh",
        "split": "train",
        "actual": False,
        "reason": "Approved SSH without reported weaknesses.",
        "findings": [{"service": "ssh", "port": 22}],
    },
    {
        "id": "approved-web",
        "split": "train",
        "actual": False,
        "reason": "Approved HTTP service without reported weaknesses.",
        "findings": [{"service": "http", "port": 80}],
    },
    {
        "id": "no-findings",
        "split": "train",
        "actual": False,
        "reason": "No alert evidence is supplied.",
        "findings": [],
    },
    {
        "id": "header-only",
        "split": "train",
        "actual": False,
        "reason": "An isolated missing header is below the alert threshold.",
        "findings": [{"description": "Missing X-Frame-Options header"}],
    },
    {
        "id": "telnet",
        "split": "train",
        "actual": True,
        "reason": "Telnet exposure requires an alert under the lab policy.",
        "findings": [{"service": "telnet", "port": 23}],
    },
    {
        "id": "sql-injection",
        "split": "train",
        "actual": True,
        "reason": "The scenario assumes a verified SQL injection.",
        "findings": [{"cwe": "CWE-89"}],
    },
    {
        "id": "public-git",
        "split": "train",
        "actual": True,
        "reason": "The scenario assumes confirmed public Git metadata.",
        "findings": [{"description": "Public access to /.git/HEAD confirmed"}],
    },
    {
        "id": "legacy-apache",
        "split": "train",
        "actual": True,
        "reason": "Legacy Apache requires remediation under the lab policy.",
        "findings": [{"product": "Apache httpd", "version": "2.2.34"}],
    },
    {
        "id": "test-ssh-web",
        "split": "test",
        "actual": False,
        "reason": "Two approved services without reported weaknesses.",
        "findings": [
            {"service": "ssh", "port": 22},
            {"service": "http", "port": 8080},
        ],
    },
    {
        "id": "test-header-web",
        "split": "test",
        "actual": False,
        "reason": "Approved web service with one below-threshold header issue.",
        "findings": [
            {"service": "http", "port": 8080},
            {"description": "Missing X-Frame-Options header"},
        ],
    },
    {
        "id": "test-telnet-web",
        "split": "test",
        "actual": True,
        "reason": "Telnet exposure remains actionable alongside HTTP.",
        "findings": [
            {"service": "telnet", "port": 23},
            {"service": "http", "port": 8080},
        ],
    },
    {
        "id": "test-sqli-ssh",
        "split": "test",
        "actual": True,
        "reason": "Verified SQL injection remains actionable alongside SSH.",
        "findings": [
            {"cwe": "CWE-89"},
            {"service": "ssh", "port": 22},
        ],
    },
    {
        "id": "test-blocked-git",
        "split": "test",
        "actual": False,
        "reason": "Git access is explicitly blocked; no metadata is exposed.",
        "findings": [
            {"description": "Access to /.git/ is blocked; no metadata exposed"},
        ],
    },
    {
        "id": "test-expired-certificate",
        "split": "test",
        "actual": True,
        "reason": "An expired production certificate requires an alert.",
        "findings": [
            {"description": "Production TLS certificate has expired"},
        ],
    },
]


def main():
    output = ROOT / "data/samples/tree_dataset.json"
    dataset = {
        "dataset_type": "synthetic_manual_labels",
        "purpose": "Educational demonstration, not a real-world benchmark",
        "cases": SCENARIOS,
    }
    output.write_text(
        json.dumps(dataset, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    train = sum(case["split"] == "train" for case in SCENARIOS)
    test = sum(case["split"] == "test" for case in SCENARIOS)

    print("Training scenarios:", train)
    print("Test scenarios:", test)
    print("Saved:", output)


if __name__ == "__main__":
    main()

