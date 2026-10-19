#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Fixed, isolated lab target: 192.0.2.2:8000. No target arguments accepted.
if [ "$#" -ne 0 ]; then
  echo "Usage: bash run_system.sh (fixed lab target 192.0.2.2)" >&2
  exit 2
fi
exec .venv/bin/python python/live_scan.py
