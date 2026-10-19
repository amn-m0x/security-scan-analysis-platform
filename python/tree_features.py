"""Extract features from findings without using labels or rule scores."""

FEATURE_NAMES = [
    "telnet_service",
    "sql_injection_cwe",
    "git_mentioned",
    "legacy_apache",
    "missing_frame_header",
]


def extract_features(findings):
    if not isinstance(findings, list):
        raise ValueError("findings must be a list.")
    if not all(isinstance(item, dict) for item in findings):
        raise ValueError("Each finding must be an object.")

    def text(item, field):
        return str(item.get(field) or "").lower()

    features = [
        any(text(f, "service") == "telnet" for f in findings),
        any(text(f, "cwe") == "cwe-89" for f in findings),
        any(".git" in text(f, "description") for f in findings),
        any(
            "apache" in text(f, "product")
            and text(f, "version").startswith("2.2.")
            for f in findings
        ),
        any(
            "x-frame-options" in text(f, "description")
            and "missing" in text(f, "description")
            for f in findings
        ),
    ]

    return [int(value) for value in features]

