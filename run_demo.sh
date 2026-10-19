#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PYTHON="$PROJECT_DIR/.venv/bin/python"
TARGET="192.0.2.10"

if [[ ! -x "$PYTHON" ]]
then
    echo "Error: .venv Python was not found." >&2
    exit 1
fi

mkdir -p build results
RUN_DIR="$(mktemp -d "$PROJECT_DIR/results/demo-XXXXXXXX")"

echo "[1/7] Building C++ parser..."
g++ -O2 -std=c++17 -Wall -Wextra cpp/nmap_parser.cpp -o build/nmap_parser $(pkg-config --cflags --libs libxml-2.0)

echo "[2/7] Processing Nmap..."
./build/nmap_parser data/samples/nmap_sample.xml > "$RUN_DIR/nmap_parsed.json"
"$PYTHON" python/normalize_nmap.py "$RUN_DIR/nmap_parsed.json" --target "$TARGET" --output "$RUN_DIR/nmap_scan.json"

echo "[3/7] Processing Masscan..."
"$PYTHON" python/normalize_masscan.py data/samples/masscan_sample.json --target "$TARGET" --output "$RUN_DIR/masscan_scan.json"

echo "[4/7] Processing Nikto..."
"$PYTHON" python/normalize_nikto.py data/samples/nikto_sample.json --target "$TARGET" --output "$RUN_DIR/nikto_scan.json"

echo "[5/7] Merging findings..."
"$PYTHON" python/merge_scans.py "$RUN_DIR/nmap_scan.json" "$RUN_DIR/masscan_scan.json" "$RUN_DIR/nikto_scan.json" --target "$TARGET" --output "$RUN_DIR/combined_scan.json"

echo "[6/7] Training and evaluating decision tree..."
"$PYTHON" python/train_tree.py

echo "[7/7] Evaluating rules and decision tree..."
"$PYTHON" python/analyze.py "$RUN_DIR/combined_scan.json" --output "$RUN_DIR/combined_incident.json"

echo "Demo completed successfully."
echo "Results: $RUN_DIR"

