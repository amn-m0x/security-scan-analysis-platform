# Security Scan Analysis Platform

An educational platform that normalizes Nmap, Masscan and Nikto reports,
evaluates YAML security rules, and returns a separate decision-tree prediction.
It includes a Go API, a browser dashboard and a Java rule-version manager.

## Contents

- [Architecture](#architecture)
- [Install on Ubuntu](#install-on-ubuntu)
- [Run the sample demo](#run-the-sample-demo)
- [Start and test the API](#start-and-test-the-api)
- [Windows and VirtualBox access](#windows-and-virtualbox-access)
- [Manage rules with Java](#manage-rules-with-java)
- [Run local live scans](#run-local-live-scans)
- [Decision tree and evaluation](#decision-tree-and-evaluation)
- [Resume after restarting Ubuntu](#resume-after-restarting-ubuntu)
- [Troubleshooting](#troubleshooting)
- [Reproducibility and limitations](#reproducibility-and-limitations)

## Architecture

| Component | Implementation | Purpose |
| --- | --- | --- |
| Nmap XML parser | C++ and libxml2 | Extract hosts and port information |
| Normalizers and merger | Python | Convert scanner reports into a shared JSON structure |
| Expert system | Python and YAML | Apply rules and calculate risk |
| Decision tree | Python and scikit-learn | Predict an alert using extracted features |
| REST API | Go with a Python bridge | Analyze reports and retain recent results |
| Dashboard | HTML, CSS and JavaScript | Upload reports and inspect both assessments |
| Rule manager | Java with a Python validator | Snapshot, list and restore rule versions |

The normalized scan contains `scan_id`, `timestamp`, `target` and `findings`.
Analysis adds `incident` for the rule assessment and `decision_tree` for the
model prediction. The tree does not replace the rule-engine risk score.

## Install on Ubuntu

### Prepare the virtual machine

Install Ubuntu Server in VirtualBox, create a regular user, and log in.
Enable a NAT network adapter with its cable connected. Internet access is
needed for system packages, Git and Python dependencies.

Commands below run in **Ubuntu**, unless explicitly labelled **Windows
PowerShell**. Run project commands from the repository root.

The demonstrated setup used Python 3.14, Go 1.26 and JDK 25. These are
observed versions, not established minimum requirements. The Java source
uses `HexFormat`, so it requires JDK 17 or newer. Python must be compatible
with the scikit-learn version pinned in `requirements.txt`.

### Install build tools

```bash
sudo apt update
sudo apt install -y git build-essential pkg-config libxml2-dev python3-venv python3-pip golang-go default-jdk curl openssh-server
```

Check the available tools:

```bash
python3 --version
g++ --version
pkg-config --modversion libxml-2.0
go version
javac -version
```

### Clone and install Python dependencies

```bash
mkdir -p ~/projects
cd ~/projects
git clone https://github.com/amn-m0x/security-scan-analysis-platform.git
cd security-scan-analysis-platform
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If the repository already exists, enter its directory instead of cloning
over it. Do not discard local changes to repeat installation.

## Run the sample demo

```bash
bash -n run_demo.sh
bash run_demo.sh
```

The first command checks shell syntax. The second performs seven stages:

1. Build the C++ Nmap parser.
2. Normalize the Nmap fixture.
3. Normalize the Masscan fixture.
4. Normalize the Nikto fixture.
5. Merge the findings.
6. Train and evaluate the decision tree.
7. Analyze the combined report with both methods.

This demo reads committed fixtures; it does **not** run live scanners.
Expected results for the supplied fixtures and rules are six findings,
a rule risk score of `9.0`, and a positive tree prediction.
Successful execution ends with `Demo completed successfully.`

Each execution creates a separate `results/demo-*` directory and prints
its absolute path. It contains `combined_scan.json` (normalized input)
and `combined_incident.json` (analysis output), plus intermediate reports.

For the examples below, replace the placeholder with the directory printed
by your own run. Set this variable again in each new Ubuntu terminal:

```bash
RUN_DIR="/absolute/path/printed/by/the/demo"
```

Re-run analysis directly:

```bash
.venv/bin/python python/analyze.py "$RUN_DIR/combined_scan.json" --output "$RUN_DIR/reanalysis.json"
```

## Start and test the API

Train the model first by running the demo, or by following the separate
training command below. Then build and start the API from the project root:

```bash
mkdir -p build results
go build -o build/api go/api.go
./build/api
```

Keep this terminal open. The expected startup message includes
`API listening on http://127.0.0.1:8080`. Use `Ctrl+C` in this terminal to
stop the foreground server. Run only one server on this port.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/analyze` | Analyze a normalized JSON scan |
| GET | `/incidents` | Return stored analysis reports |
| GET | `/` | Serve the dashboard |

In a **second Ubuntu terminal**, enter the project directory and set
`RUN_DIR` to the demo directory:

```bash
cd ~/projects/security-scan-analysis-platform
RUN_DIR="/absolute/path/printed/by/the/demo"
curl --fail-with-body -sS -H "Content-Type: application/json" --data-binary "@$RUN_DIR/combined_scan.json" http://127.0.0.1:8080/analyze -o results/api_with_tree.json
.venv/bin/python -m json.tool results/api_with_tree.json
curl --fail-with-body -sS http://127.0.0.1:8080/incidents
```

The POST response should include `incident` and `decision_tree`. For the
combined fixture, both `detected` values and `agrees_with_rules` should be
`true`. The API retains up to 100 reports in memory; restarting the server
clears this history. Scan inputs are limited to 2 MiB.

## Windows and VirtualBox access

### Enable SSH in Ubuntu

```bash
sudo systemctl enable --now ssh
systemctl is-active ssh
```

The expected status is `active`.

### Configure VirtualBox NAT forwarding

In the VM network settings, open the NAT adapter's port-forwarding dialog
and add this TCP rule:

| Field | Value |
| --- | --- |
| Name | SSH |
| Protocol | TCP |
| Host IP | `127.0.0.1` |
| Host port | `2222` |
| Guest IP | Current guest NAT address, `10.0.2.15` in the demonstrated setup |
| Guest port | `22` |

Check the current guest address with `ip -4 addr` in Ubuntu. If it changes,
update the forwarding rule. The API itself remains bound to guest loopback.

### Open the SSH tunnel

In **Windows PowerShell**, replace `YOUR_UBUNTU_USER` with your Ubuntu
username (`amin` in the demonstrated setup):

```powershell
ssh -N -L 18080:127.0.0.1:8080 -p 2222 YOUR_UBUNTU_USER@127.0.0.1
```

Enter the Ubuntu user's password when prompted. Password entry is not
echoed. A quiet, waiting terminal is normal for this tunnel; keep it open.
Open this address in the Windows browser:

```text
http://127.0.0.1:18080
```

Click **Refresh reports** to view the report submitted through the API.
The report displays rule risk, findings, recommendations, the tree alert
and agreement between the methods.

### Upload a report through the dashboard

To obtain a predictable transfer path, run in Ubuntu after setting `RUN_DIR`:

```bash
cp "$RUN_DIR/combined_scan.json" results/dashboard-input.json
```

In a **new Windows PowerShell window**, leaving the tunnel open:

```powershell
scp -P 2222 YOUR_UBUNTU_USER@127.0.0.1:projects/security-scan-analysis-platform/results/dashboard-input.json "$env:USERPROFILE\Downloads\dashboard-input.json"
```

In the dashboard, choose this downloaded file and click **Analyze JSON**.
Upload normalized JSON, not raw Nmap XML or raw scanner JSON.

## Manage rules with Java

Run all commands from the project root:

```bash
mkdir -p build/java
javac -d build/java java/RuleManager.java
.venv/bin/python python/validate_rules.py rules/rules.yaml
java -cp build/java RuleManager list
```

Create a snapshot using a new name:

```bash
java -cp build/java RuleManager snapshot local-demo-01
```

Snapshots are stored in `rules/versions/`. Existing names are not
overwritten. Names allow 1–64 letters, digits, hyphens or underscores,
starting with a letter or digit. Snapshot creation copies the file and
checks its bytes; validate the active rules separately before snapshotting.

To restore that snapshot (this changes the active rules):

```bash
java -cp build/java RuleManager restore local-demo-01
```

Restoration validates a staged copy with `python/validate_rules.py`, backs
up existing active rules under `rules/backups/`, then atomically replaces
`rules/rules.yaml`. Invalid rules are rejected before replacement.
The virtual environment is needed for validation. A new request is needed
to analyze a report using changed rules; stored historical reports do not
automatically change.

## Run local live scans

These steps are separate from the sample demo. Only scan systems you own
or have permission to test. Keep the API running for the loopback examples.
Run the following commands in Ubuntu from the project root.

### Install scanners

```bash
sudo apt install -y nmap masscan perl libxml-writer-perl
mkdir -p ~/tools
git clone https://github.com/sullo/nikto.git ~/tools/nikto
perl ~/tools/nikto/program/nikto.pl -Version
nmap --version
masscan --version
```

Clone Nikto only if `~/tools/nikto` does not already exist. The demonstrated
lab used Nikto 2.6.1. Cloning the default branch may obtain a different
version; record the version and commit used in a new experiment:

```bash
git -C ~/tools/nikto rev-parse HEAD
```

### Nmap against the local VM

The demo builds `build/nmap_parser`. If needed, build it separately:

```bash
mkdir -p build results/live
g++ -O2 -std=c++17 -Wall -Wextra cpp/nmap_parser.cpp -o build/nmap_parser $(pkg-config --cflags --libs libxml-2.0)
nmap -sT -sV -p 22,80,8080 -oX results/live/nmap.xml 127.0.0.1
./build/nmap_parser results/live/nmap.xml > results/live/nmap_parsed.json
.venv/bin/python python/normalize_nmap.py results/live/nmap_parsed.json --target 127.0.0.1 --output results/live/nmap_scan.json
.venv/bin/python python/analyze.py results/live/nmap_scan.json --output results/live/nmap_incident.json
```

### Nikto against the local API

```bash
mkdir -p results/live
perl ~/tools/nikto/program/nikto.pl -h http://127.0.0.1:8080 -Format json -o "$PWD/results/live/nikto.json"
.venv/bin/python python/normalize_nikto.py results/live/nikto.json --target 127.0.0.1 --output results/live/nikto_scan.json
.venv/bin/python python/analyze.py results/live/nikto_scan.json --output results/live/nikto_incident.json
```

Wait for the scanner to finish before normalizing its output. Actual
findings depend on tool versions and the running service. Missing web
headers or unusual HTTP responses do not by themselves prove an incident.

### Masscan in an isolated network namespace

This lab uses `192.0.2.1/30` and `192.0.2.2/30` on a local veth pair.
It does not require scanning the external network. First inspect existing
namespaces; do not recreate an already running `masscan-lab`:

```bash
sudo ip netns list
```

For a fresh lab:

```bash
sudo ip netns add masscan-lab
sudo ip link add mc-host type veth peer name mc-target
sudo ip link set mc-target netns masscan-lab
sudo ip addr add 192.0.2.1/30 dev mc-host
sudo ip link set mc-host up
sudo ip netns exec masscan-lab ip addr add 192.0.2.2/30 dev mc-target
sudo ip netns exec masscan-lab ip link set mc-target up
sudo ip netns exec masscan-lab ip link set lo up
mkdir -p results/masscan-web results/live
sudo ip netns exec masscan-lab python3 -m http.server 8000 --bind 192.0.2.2 --directory results/masscan-web
```

Keep this foreground web server running. In a second Ubuntu terminal,
enter the project root and run:

```bash
curl --fail -I http://192.0.2.2:8000
MC_TARGET_MAC=$(sudo ip netns exec masscan-lab cat /sys/class/net/mc-target/address)
sudo masscan 192.0.2.2 -p8000 -e mc-host --router-mac "$MC_TARGET_MAC" --rate 10 --wait 5 -oJ results/live/masscan.json
.venv/bin/python python/normalize_masscan.py results/live/masscan.json --target 192.0.2.2 --output results/live/masscan_scan.json
.venv/bin/python python/analyze.py results/live/masscan_scan.json --output results/live/masscan_incident.json
```

Expected lab discovery: TCP port `8000` open. An open port does not
automatically mean a rule alert. Masscan does not identify a service merely
from its port number in this normalization pipeline.

To remove this lab, stop its foreground web server with `Ctrl+C`, then run:

```bash
sudo ip netns delete masscan-lab
```

The namespace and its veth peer are temporary and must be recreated after
a VM restart. Saved scan files persist. Do not merge this target with
loopback reports: merged reports must describe the same target.

## Decision tree and evaluation

The dataset is committed as `data/samples/tree_dataset.json`. Train separately:

```bash
.venv/bin/python python/train_tree.py
```

Training produces:

```text
results/decision_tree.joblib
results/decision_tree.txt
results/tree_evaluation.json
```

Train before using the CLI or API. The demo retrains on each run.
Only load trusted, locally generated model artifacts. Retrain after
changing the scikit-learn version or feature schema.

The model uses indicators for Telnet, SQL injection CWE, Git metadata,
legacy Apache and missing frame-protection headers. It is trained on eight
synthetic scenarios and evaluated on six separate synthetic scenarios.
The examples share feature families and are not an independent real-world
security benchmark.

| Tree test metric | Observed value |
| --- | ---: |
| True positives | 2 |
| False positives | 1 |
| False negatives | 1 |
| True negatives | 2 |
| Precision | 0.6667 |
| Recall | 0.6667 |
| F1 | 0.6667 |

The blocked-Git example is a false positive and the expired-certificate
example is a false negative. Agreement with rules does not prove either
method is correct. Rule-engine scores are not calibrated probabilities.
The rule engine's separate eight-case evaluation previously yielded
precision, recall and F1 of `0.75`; these numbers use a different test set
and must not be treated as a direct model comparison.

## Resume after restarting Ubuntu

In Ubuntu:

```bash
cd ~/projects/security-scan-analysis-platform
source .venv/bin/activate
```

Existing builds and model files persist. If the model is missing, run
`python python/train_tree.py`; if the API binary is missing, rebuild it
with `go build -o build/api go/api.go`. Then start the API:

```bash
./build/api
```

Reopen the Windows SSH tunnel and browser as described above. Resubmit a
normalized report because API history is in memory. Recreate the namespace
only when another live Masscan lab run is needed.

## Troubleshooting

| Symptom | Check or action |
| --- | --- |
| API connection refused | In Ubuntu run `ss -ltnp 'sport = :8080'`; start the API from the project root if no listener exists. |
| Windows site cannot be reached | Verify API, SSH service, NAT forwarding and the open tunnel; use `http://127.0.0.1:18080`. |
| Address already in use | Inspect the listener before starting a second API or tunnel; reuse or stop the identified process. |
| Model missing or incompatible | Run `.venv/bin/python python/train_tree.py` from the root. |
| Python module missing | Use `.venv/bin/python -m pip install -r requirements.txt`. |
| `go --version` fails | The correct command is `go version`. |
| `libxml-2.0` unavailable | Install `libxml2-dev` and `pkg-config`. |
| Old Nikto reports an SSL initialization error | Use the explicit `~/tools/nikto/program/nikto.pl` installation instead of the old executable. |
| Java version already exists | Choose a new snapshot name; snapshots are not overwritten. |
| Java restore rejected | Read validator output and correct the selected YAML; invalid rules should not be activated. |
| Dashboard shows old HTML | Reload with `Ctrl+F5`, then click **Refresh reports**. |
| Lost Markdown characters | Transfer the README file with SCP instead of retyping it in the VM console. |

## Reproducibility and limitations

- `results/`, `build/`, `.venv/` and rule backups are generated local artifacts
  excluded from version control. Commit source, dependency declarations,
  fixtures and intended rule versions.
- A fresh clone requires dependency installation, model training and builds.
  The seven-stage demo has been demonstrated in the development VM; the
  entire installation guide still requires a clean-environment verification.
- Live scans were exercised separately in the lab. They are not automated
  by `run_demo.sh`, and their exact findings may vary.
- The API is intended for local educational use, not an authenticated
  production service. Findings require review and do not establish a
  successful attack.
- Record tool versions, repository commit, commands and output screenshots
  in the final report. Include installation and execution instructions in
  the report itself, rather than referring only to this README.
- Analysis of the assignment's original SDL_Moskalev repository is pending
  identification of its exact URL.

## Integrated live scanning

The dashboard now supports starting a fixed-target lab scan through
`POST /scan`, with progress available through `GET /scan/status?id=JOB_ID`.
Nmap, Masscan and Nikto run concurrently in the Python runner.
Go manages the background job.

See [the live scanning guide](docs/LIVE_SCAN.md) for setup, permissions,
execution and cleanup. The sample demo remains fixture-based.
