#!/usr/bin/env bash
# Double-click to stop the lab and free its memory. Lab data is deleted; the next start is fresh.
cd "$(dirname "$0")" || exit 1
. ./lib.sh
echo "=== Security lab: stopping ==="
lab_down
rm -rf "$OUT_DIR"
echo "Stopped. All lab containers and their data are removed; memory is freed."
read -r -p "Press Enter to close." _
