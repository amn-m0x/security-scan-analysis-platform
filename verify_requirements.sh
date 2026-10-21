#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p build/java results
go build -o build/scan_runner-next go/scanner/main.go
mv build/scan_runner-next build/scan_runner
go build -o build/api-next go/api.go
mv build/api-next build/api
javac -d build/java java/RuleManager.java
GO111MODULE=off go test -race -v ./go/scanner
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
.venv/bin/python python/validate_rules.py rules/rules.yaml
echo 'PASS: Go collector and Java rule management verified'
echo 'Live VM check: bash run_system.sh > results/requirements-live.json'
echo 'Then: .venv/bin/python python/verify_live_report.py results/requirements-live.json'
