#!/usr/bin/env bash
# Prints PASS or FAIL for each part of the lab, with the reason. Exit 0 only if all pass.
# Writes $OUT_DIR/checks.tsv (part, result, measured value, reason) for the scorecard.
set -u
. "$(dirname "$0")/lib.sh"
ALERT_WAIT="${ALERT_WAIT:-180}"
TSV="$OUT_DIR/checks.tsv"; printf 'part\tresult\tvalue\treason\n' > "$TSV"
fails=0
rec() { # part result value reason
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$TSV"
  printf '%-26s %s  %s\n' "$1" "$2" "$4"
  [ "$2" = PASS ] || fails=$((fails+1))
}

# 1. containers
want="juiceshop waf suricata wazuh.manager wazuh.indexer wazuh.dashboard"
running=$(dc ps --status running --services 2>/dev/null | tr '\n' ' ')
missing=""; for s in $want; do case " $running " in *" $s "*) ;; *) missing="$missing $s";; esac; done
n_run=$(echo "$running" | wc -w | tr -d ' ')
if [ -z "$missing" ]; then rec containers_running PASS "$n_run" "all 6 lab containers are running"
else rec containers_running FAIL "$n_run" "not running:$missing"; fi

# 2. normal traffic still allowed through the WAF
code=$(cat "$OUT_DIR/normal_status" 2>/dev/null || http_code "$WAF_URL/rest/products/search?q=apple")
if [ "$code" = 200 ]; then rec waf_allows_normal_traffic PASS "$code" "a normal product search returned HTTP 200"
else rec waf_allows_normal_traffic FAIL "$code" "a normal product search returned HTTP $code (expected 200)"; fi

# 3. attacks blocked
if [ -f "$OUT_DIR/attacks.tsv" ]; then
  sent=$(awk 'NR>1' "$OUT_DIR/attacks.tsv" | wc -l | tr -d ' ')
  blocked=$(awk -F'\t' 'NR>1 && $5==403' "$OUT_DIR/attacks.tsv" | wc -l | tr -d ' ')
  if [ "$sent" -gt 0 ] && [ "$sent" = "$blocked" ]; then rec waf_blocks_attacks PASS "$blocked/$sent" "the WAF returned 403 for all $sent attacks"
  else
    notb=$(awk -F'\t' 'NR>1 && $5!=403 {printf " %s(%s)", $2, $5}' "$OUT_DIR/attacks.tsv")
    rec waf_blocks_attacks FAIL "$blocked/$sent" "only $blocked of $sent attacks got 403; not blocked:$notb"
  fi
else
  rec waf_blocks_attacks FAIL "0/0" "no attack has been run yet (run attack-demo first)"
fi

# 4 + 5. alerts in Wazuh (polls the indexer until both appear or ALERT_WAIT seconds pass)
start=$(cat "$OUT_DIR/attack_start" 2>/dev/null || date +%s)
t0=$(date +%s); waf_n=error; ids_n=error; waf_t=""; ids_t=""
while :; do
  waf_n=$(alert_count "$WAF_ALERT_Q"); ids_n=$(alert_count "$IDS_ALERT_Q"); now=$(date +%s)
  [ -z "$waf_t" ] && [ "$waf_n" != error ] && [ "$waf_n" -ge 1 ] && waf_t=$((now-start))
  [ -z "$ids_t" ] && [ "$ids_n" != error ] && [ "$ids_n" -ge 1 ] && ids_t=$((now-start))
  if [ -n "$waf_t" ] && [ -n "$ids_t" ]; then break; fi
  if [ $((now-t0)) -ge "$ALERT_WAIT" ]; then break; fi
  sleep 3
done
echo "${waf_t:-}" > "$OUT_DIR/waf_seconds"; echo "${ids_t:-}" > "$OUT_DIR/ids_seconds"
curl -sk -m 15 -u "$WAZUH_USER:$WAZUH_PASS" -G "$INDEXER_URL/wazuh-alerts-*/_search" --data-urlencode "q=$WAF_ALERT_Q" --data-urlencode "size=1" > "$OUT_DIR/waf_alert_sample.json" 2>/dev/null
curl -sk -m 15 -u "$WAZUH_USER:$WAZUH_PASS" -G "$INDEXER_URL/wazuh-alerts-*/_search" --data-urlencode "q=$IDS_ALERT_Q" --data-urlencode "size=1" > "$OUT_DIR/ids_alert_sample.json" 2>/dev/null
if [ -n "$waf_t" ]; then rec wazuh_has_waf_alert PASS "$waf_n" "Wazuh holds $waf_n WAF block alerts (rule 100101)"
else rec wazuh_has_waf_alert FAIL "$waf_n" "no WAF alert (rule 100101) in Wazuh after ${ALERT_WAIT}s (count: $waf_n)"; fi
if [ -n "$ids_t" ]; then rec wazuh_has_ids_alert PASS "$ids_n" "Wazuh holds $ids_n Suricata alerts"
else rec wazuh_has_ids_alert FAIL "$ids_n" "no Suricata alert in Wazuh after ${ALERT_WAIT}s (count: $ids_n)"; fi

# 6. dashboard
code=$(http_code "$DASH_URL/app/login")
if [ "$code" = 200 ]; then rec dashboard_loads PASS "$code" "the Wazuh dashboard login page returned HTTP 200"
else rec dashboard_loads FAIL "$code" "the Wazuh dashboard returned HTTP $code (expected 200)"; fi

if [ -n "$waf_t" ] && [ -n "$ids_t" ]; then
  echo "Seconds from first attack to alert in Wazuh: WAF ${waf_t}s, Suricata ${ids_t}s"
fi
if [ "$fails" -eq 0 ]; then echo "OVERALL: PASS"; exit 0; else echo "OVERALL: FAIL ($fails part(s))"; exit 1; fi
