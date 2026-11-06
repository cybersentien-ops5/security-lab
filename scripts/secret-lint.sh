#!/usr/bin/env bash
# Fails if any tracked file contains a key or token pattern. The lab's well-known default
# demo logins (Wazuh single-node defaults) are not secrets and are not matched.
set -u
cd "$(dirname "$0")/.."
PATTERNS='-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(live|proj)?-?[A-Za-z0-9]{32,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|hf_[A-Za-z0-9]{34}|-----BEGIN PGP PRIVATE KEY BLOCK-----|https?://[^/ :]+:[^@ /$]{6,}@'
hits=$(git ls-files -z | grep -zv '^scripts/secret-lint.sh$' | xargs -0 grep -nIE -e "$PATTERNS" 2>/dev/null || true)
if [ -n "$hits" ]; then
  echo "Secret or key pattern found (file:line, value hidden):"
  echo "$hits" | cut -d: -f1,2
  exit 1
fi
echo "No key or token patterns found in $(git ls-files | wc -l | tr -d ' ') tracked files."
