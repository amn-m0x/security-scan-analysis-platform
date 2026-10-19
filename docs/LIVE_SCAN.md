# Integrated live lab scan

This extension adds a fixed-target live pipeline. The only target is
`192.0.2.2`, TCP port `8000`, inside the local `masscan-lab` network namespace.
The API rejects other targets. The three scanners run concurrently in the
Python runner; Go starts a background job so HTTP requests do not wait for
completion. This is not an arbitrary-target scanner service.

## Prerequisites

From the project root, install system dependencies if missing:

```bash
sudo apt update
sudo apt install -y nmap masscan perl libxml-writer-perl libcap2-bin iproute2
```

Nikto must exist at `~/tools/nikto/program/nikto.pl`. Use the installation
instructions in README if needed. Build the C++ parser and train the model
using `bash run_demo.sh` if their generated artifacts are missing.

## Start the lab

In an Ubuntu terminal, run from the project root:

```bash
bash setup_lab.sh
```

The script creates the namespace and veth pair, records the target MAC,
then runs a foreground web server. Keep this terminal open. It refuses to
replace an existing lab. If setup fails partway through, inspect
`sudo ip netns list` and `ip link show mc-host` before retrying.

**Privilege change:** setup uses sudo for network configuration and grants
`cap_net_raw,cap_net_admin` to the installed Masscan binary using `setcap`.
This lets the ordinary user run Masscan without running the API as root.
These capabilities apply to the binary, not just this application, persist
across reboot, and may be cleared by package upgrades. On a shared machine,
review this choice with its administrator. The intended environment is a
personal educational VM. Neither the API nor the runner invokes sudo.

## Command-line pipeline

In another Ubuntu terminal:

```bash
cd ~/projects/security-scan-analysis-platform
bash run_system.sh
```

The script takes no target arguments. It runs Nmap, Masscan and Nikto
concurrently, normalizes their real output, merges reports for the same
host, and invokes the existing rules and decision-tree bridge.
Each run creates `results/live-*` containing raw output, logs,
`scanner_status.json`, normalized files, `combined_scan.json` and
`incident.json`. The final report is also printed as JSON.

Each scanner has a six-minute timeout. Failure of any scanner prevents a
complete assessment; see the status file and individual logs. Empty findings
alone must not be interpreted as successful scanning or proof of safety.
CLI runs save results but do not insert them into the running API history.
Do not run a CLI scan and an API scan simultaneously; the API's one-job
limit does not cover independently started CLI processes.

## Build and run the API

```bash
go build -o build/api-next go/api.go
```

Stop the previous API process using its terminal's Ctrl+C (or its verified
PID if it was started in the background), then run:

```bash
mv build/api-next build/api
./build/api
```

Keep the API terminal open. In a second terminal, start a job:

```bash
curl --fail-with-body -sS -H "Content-Type: application/json" --data '{"target":"192.0.2.2"}' http://127.0.0.1:8080/scan
```

The response is HTTP 202 with `id`, `status` and `target`. Substitute the
returned ID to poll:

```bash
curl --fail-with-body -sS "http://127.0.0.1:8080/scan/status?id=JOB_ID"
```

Status becomes `completed` with a report, or `failed` with an error. Only
the latest job status is retained. Successful jobs also enter the existing
100-report in-memory history. Restarting the API loses this history and job
state; saved files remain. Do not restart during a scan: child processes may
continue until their own completion or timeout.

Concurrent POST requests while a job is running return HTTP 409. Malformed
requests and targets other than the fixed lab address return HTTP 400.
The JSON Content-Type is required. Keep the service bound to localhost and
use the existing SSH tunnel; this is not an authenticated public API.

## Dashboard

Open `http://127.0.0.1:18080` through the existing Windows SSH tunnel.
Reload with Ctrl+F5. Click **Start lab scan**; the target is read-only.
The dashboard polls job status and refreshes reports on completion.
A severity distribution is included for each report, including `info` and
`unknown`. It counts normalized finding severity, not rule risk. It may
legitimately show mostly informational findings.

## Validation status

Python, Bash and JavaScript syntax checks passed in the preparation
environment. Two simulated-scanner tests verify concurrency and failure
propagation:

```bash
.venv/bin/python -m unittest discover -s tests -p test_live_scan.py -v
```

Go compilation and a live end-to-end dashboard scan were verified in the
Ubuntu VM on 2026-10-19. All three scanners completed successfully and their
execution intervals overlapped.

| Scanner | Duration in seconds | Findings |
| --- | ---: | ---: |
| Nmap | 8.44 | 1 |
| Masscan | 6.36 | 1 |
| Nikto | 76.90 | 14 |

The combined report contained 16 findings for 192.0.2.2. The current rules
returned risk 0 and no alert; the decision tree also returned no alert.
These results do not establish that the target is secure. Nikto messages
remain scanner observations requiring review.

The standalone CLI entry point has not yet been demonstrated separately;
the dashboard uses the same Python runner.

## Stop and clean up

Wait for scans to finish. Stop the lab web server with Ctrl+C. Then:

```bash
sudo ip netns delete masscan-lab
```

To revoke the Masscan capability grant after the lab:

```bash
sudo setcap -r "$(readlink -f "$(command -v masscan)")"
```

Recreate the namespace after reboot. Saved outputs and model files persist.
