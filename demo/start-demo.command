#!/usr/bin/env bash
# Double-click to start the security lab on a Mac (Docker Desktop).
cd "$(dirname "$0")" || exit 1
. ./lib.sh
echo "=== Security lab: starting ==="

if ! docker info >/dev/null 2>&1; then
  echo "FAIL: Docker Desktop is not running."
  echo "  Open Docker Desktop (Applications > Docker), wait for 'Engine running', then double-click this file again."
  read -r -p "Press Enter to close." _; exit 1
fi

mem=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
# 6 GB setting shows as a little under 6,000,000,000 bytes inside Docker's VM
if [ "$mem" -lt 5800000000 ]; then
  echo "FAIL: Docker Desktop has only $((mem/1000000000)) GB of memory. The lab needs at least 6 GB."
  echo "  Fix: Docker Desktop > Settings (gear icon) > Resources > Memory limit: set 8 GB > Apply & restart."
  echo "  Then double-click this file again."
  read -r -p "Press Enter to close." _; exit 1
fi

# The Wazuh indexer needs this kernel setting inside Docker Desktop's VM (resets when Docker restarts)
docker run --rm --privileged --pid=host busybox:1.36.1 nsenter -t 1 -m -u -n -i sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true

echo "Starting containers (the first run downloads about 4 GB and can take 10-15 minutes)..."
lab_up || { echo "FAIL: could not start the lab. Run check-demo.command to see why."; read -r -p "Press Enter to close." _; exit 1; }

echo "Waiting until every part is healthy (up to 10 minutes)..."
if ! lab_wait 600; then
  echo "FAIL: the lab did not become healthy in 10 minutes. Run check-demo.command to see which part."
  read -r -p "Press Enter to close." _; exit 1
fi

open "$DASH_URL"
open "$WAF_URL"
cat <<INFO

=== Lab is ready ===
Wazuh dashboard (SIEM):  $DASH_URL
   login: $WAZUH_USER   password: $WAZUH_PASS
   (your browser warns about the lab's self-made certificate: click Advanced > Proceed)
Juice Shop behind the WAF:  $WAF_URL
Next: double-click attack-demo.command
INFO
read -r -p "Press Enter to close this window (the lab keeps running)." _
