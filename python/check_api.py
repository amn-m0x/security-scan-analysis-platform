import json
from pathlib import Path
from urllib.request import Request, urlopen

body = Path("results/combined_scan.json").read_bytes()

request = Request(
    "http://127.0.0.1:8080/analyze",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)

with urlopen(request, timeout=20) as response:
    status = response.status
    result = json.load(response)

assert status == 200
assert len(result["findings"]) == 6
assert result["incident"]["detected"] is True
assert result["incident"]["risk_score"] == 9.0
assert len(result["incident"]["triggering_findings"]) == 5

Path("results/api_response.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)

with urlopen("http://127.0.0.1:8080/incidents", timeout=10) as response:
    history = json.load(response)

assert any(
    report["scan_id"] == result["scan_id"]
    and report["incident"] == result["incident"]
    for report in history
)

print("HTTP status:", status)
print("Target:", result["target"])
print("Findings:", len(result["findings"]))
print("Risk score:", result["incident"]["risk_score"])
print("Stored reports:", len(history))
print("PASS: Go API -> Python engine -> JSON response")
