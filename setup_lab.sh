#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p results/masscan-web
if sudo ip netns list | grep -q '^masscan-lab\b'; then
  echo "masscan-lab already exists. Reuse its server; do not start another." >&2
  exit 1
fi
if ip link show mc-host >/dev/null 2>&1; then
  echo "mc-host already exists; inspect the existing lab before continuing." >&2
  exit 1
fi
sudo ip netns add masscan-lab
sudo ip link add mc-host type veth peer name mc-target
sudo ip link set mc-target netns masscan-lab
sudo ip addr add 192.0.2.1/30 dev mc-host
sudo ip link set mc-host up
sudo ip netns exec masscan-lab ip addr add 192.0.2.2/30 dev mc-target
sudo ip netns exec masscan-lab ip link set mc-target up
sudo ip netns exec masscan-lab ip link set lo up
sudo ip netns exec masscan-lab cat /sys/class/net/mc-target/address > results/lab-target-mac.txt
# Masscan needs raw network access; the API itself must NOT run as root.
MASSCAN_BIN="$(readlink -f "$(command -v masscan)")"
sudo setcap cap_net_raw,cap_net_admin+ep "$MASSCAN_BIN"
echo "Lab ready at http://192.0.2.2:8000. Keep this terminal open. Ctrl+C stops the web server."
sudo ip netns exec masscan-lab python3 -m http.server 8000 --bind 192.0.2.2 --directory results/masscan-web
