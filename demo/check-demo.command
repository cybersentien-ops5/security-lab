#!/usr/bin/env bash
# Double-click to print PASS or FAIL for each part of the lab.
cd "$(dirname "$0")" || exit 1
echo "=== Security lab: check ==="
if ! docker info >/dev/null 2>&1; then echo "docker                     FAIL  Docker Desktop is not running"; read -r -p "Press Enter to close." _; exit 1; fi
ALERT_WAIT=30 bash ./check.sh
read -r -p "Press Enter to close." _
