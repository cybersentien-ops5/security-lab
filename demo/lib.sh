#!/usr/bin/env bash
# Shared helpers for the lab scripts (GitHub Actions and macOS). bash 3.2 compatible.
LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$LAB_ROOT/lab/compose.yml"
OUT_DIR="${OUT_DIR:-$LAB_ROOT/demo/.last-run}"
mkdir -p "$OUT_DIR"

# Well-known default logins of the synthetic lab (Wazuh single-node defaults). Lab only.
WAZUH_USER="admin"; WAZUH_PASS="SecretPassword"
API_USER="wazuh-wui"; API_PASS='MyS3cr37P450r.*-'
WAF_URL="http://127.0.0.1:8080"
DASH_URL="https://127.0.0.1:8443"
INDEXER_URL="https://127.0.0.1:9200"
API_URL="https://127.0.0.1:55000"

dc() { docker compose -f "$COMPOSE_FILE" "$@"; }

lab_certs() {
  local d="$LAB_ROOT/lab/wazuh/certs"
  if [ -r "$d/root-ca.pem" ] && [ -r "$d/wazuh.dashboard.pem" ]; then return 0; fi
  echo "Creating the lab's certificates with Wazuh's own generator (first run only)..."
  dc --profile setup run --rm certs > "$OUT_DIR/certs_generator.txt" 2>&1
  local rc=$?
  tail -n 5 "$OUT_DIR/certs_generator.txt"
  # On Linux the generator writes root-owned files; make them readable by the lab containers.
  if [ ! -r "$d/root-ca.pem" ] && sudo -n true 2>/dev/null; then sudo chown -R "$(id -u):$(id -g)" "$d"; fi
  chmod -R a+rX "$d" 2>/dev/null || true
  [ "$rc" -eq 0 ] && [ -r "$d/root-ca.pem" ] && [ -r "$d/wazuh.dashboard.pem" ]
}

lab_up() { lab_certs && dc up -d; }
lab_down() { dc down -v --remove-orphans; }

# http_code URL [curl args...]
http_code() { local u="$1"; shift; curl -sk -o /dev/null -m 10 -w '%{http_code}' "$@" "$u" 2>/dev/null || true; }

# Waits until every part answers. $1 = timeout seconds (default 600)
lab_wait() {
  local limit="${1:-600}" start now c1 c2 c3 c4 c5
  start=$(date +%s)
  while :; do
    c1=$(http_code "$WAF_URL/")
    c2=$(http_code "$INDEXER_URL/_cluster/health" -u "$WAZUH_USER:$WAZUH_PASS")
    c3=$(http_code "$API_URL/security/user/authenticate" -u "$API_USER:$API_PASS" -X POST)
    c4=$(http_code "$DASH_URL/app/login")
    if dc logs suricata 2>/dev/null | grep -q "Engine started"; then c5=yes; else c5=no; fi
    now=$(date +%s)
    printf '  [%4ss] waf=%s indexer=%s wazuh-api=%s dashboard=%s suricata=%s\n' "$((now-start))" "$c1" "$c2" "$c3" "$c4" "$c5"
    if [ "$c1" = 200 ] && [ "$c2" = 200 ] && [ "$c3" = 200 ] && [ "$c4" = 200 ] && [ "$c5" = yes ]; then return 0; fi
    if [ $((now-start)) -ge "$limit" ]; then return 1; fi
    sleep 10
  done
}

# Count of Wazuh alerts matching a Lucene query string (prints a number, or "error")
alert_count() {
  local q="$1" body
  body=$(curl -sk -m 15 -u "$WAZUH_USER:$WAZUH_PASS" -G "$INDEXER_URL/wazuh-alerts-*/_count" --data-urlencode "q=$q" 2>/dev/null)
  echo "$body" | sed -n 's/.*"count":\([0-9]*\).*/\1/p' | grep . || echo error
}
WAF_ALERT_Q='rule.id:100101'
IDS_ALERT_Q='rule.groups:suricata AND data.event_type:alert'
