#!/usr/bin/env bash
# IPS test (Linux runner, root via sudo): Suricata inline in front of a small web server.
# Proves blocking, not just alerting: each attack must get NO answer from the server and be
# recorded as "blocked" in Suricata's own log, while normal requests still get HTTP 200.
set -uo pipefail
OUT="${OUT_DIR:-$PWD/out}/ips"; mkdir -p "$OUT/web" "$OUT/suricata"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PORT=9999; IMG="jasonish/suricata:7.0.17"
TSV="$OUT/results.tsv"; : > "$TSV"; fails=0
rec() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TSV"; printf '%-34s %s  %s\n' "$1" "$2" "$3"; [ "$2" = PASS ] || fails=$((fails+1)); }

echo "lab page" > "$OUT/web/index.html"
( cd "$OUT/web" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > "$OUT/web.pid" )
sleep 1

# Suricata inline: every packet to and from the web port goes through NFQUEUE 0.
# No --queue-bypass: if Suricata is not running, the traffic stops (fail closed).
docker run -d --name ips --net host --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_NICE \
  -v "$HERE/lab/suricata/ips.rules:/lab/ips.rules:ro" -v "$OUT/suricata:/var/log/suricata" \
  "$IMG" -v -q 0 -k none -S /lab/ips.rules >/dev/null
for i in $(seq 1 60); do docker logs ips 2>&1 | grep -q "Engine started" && break; sleep 2; done
docker logs ips 2>&1 | grep -q "Engine started" && rec ips_engine_inline PASS "Suricata started in NFQUEUE (inline) mode" \
  || { rec ips_engine_inline FAIL "Suricata did not start"; docker logs ips 2>&1 | tail -20; }
loaded=$(docker logs ips 2>&1 | grep -o '[0-9]* rules successfully loaded' | head -1); bad=$(docker logs ips 2>&1 | grep -c 'error parsing signature' || true)
want=$(grep -c '^drop' "$HERE/lab/suricata/ips.rules")
[ "$bad" = 0 ] && [ "${loaded%% *}" = "$want" ] && rec ips_rules_loaded PASS "$loaded (of $want), 0 parse errors" || { rec ips_rules_loaded FAIL "loaded: '$loaded' of $want, parse errors: $bad"; docker logs ips 2>&1 | grep -i 'error' | head -5; }
sudo iptables -I INPUT -i lo -p tcp --dport "$PORT" -j NFQUEUE --queue-num 0
sudo iptables -I INPUT -i lo -p tcp --sport "$PORT" -j NFQUEUE --queue-num 0

get() { curl -s -o /dev/null -m 6 -w '%{http_code}' "http://127.0.0.1:$PORT$1" 2>/dev/null; echo " rc=$?"; }

r=$(get "/index.html"); case "$r" in 200*) rec normal_request_allowed PASS "HTTP 200 through the IPS";; *) rec normal_request_allowed FAIL "got: $r";; esac

for a in "/?file=../../../../etc/passwd|path_traversal|1000201" "/?id=1%20UNION%20SELECT%20password%20FROM%20users|sql_injection|1000202" "/?host=127.0.0.1;cat%20/etc/shadow|command_injection|1000203"; do
  path="${a%%|*}"; rest="${a#*|}"; name="${rest%%|*}"; sid="${rest#*|}"
  t0=$(date +%s.%N); r=$(get "$path"); t1=$(date +%s.%N)
  sleep 1
  blocked=$(grep -c "\"signature_id\":$sid" "$OUT/suricata/eve.json" 2>/dev/null || true)
  act=$(grep "\"signature_id\":$sid" "$OUT/suricata/eve.json" 2>/dev/null | grep -o '"action":"[a-z]*"' | head -1)
  case "$r" in 200*) rec "attack_${name}_dropped" FAIL "server answered: $r";;
    *) if [ "$act" = '"action":"blocked"' ]; then rec "attack_${name}_dropped" PASS "no answer from the server ($r); Suricata recorded action blocked, sid $sid"
       else rec "attack_${name}_dropped" FAIL "no answer ($r) but Suricata did not record a block for sid $sid ($act)"; fi;;
  esac
done

r=$(get "/index.html"); case "$r" in 200*) rec normal_request_after_attacks PASS "HTTP 200 (only the attacks were dropped)";; *) rec normal_request_after_attacks FAIL "got: $r";; esac

# Fail closed: stop Suricata, the queued port must stop answering.
docker stop ips >/dev/null
r=$(get "/index.html"); case "$r" in 200*) rec fails_closed_without_ips FAIL "answered with the IPS stopped: $r";; *) rec fails_closed_without_ips PASS "no answer with the IPS stopped ($r)";; esac

sudo iptables -D INPUT -i lo -p tcp --dport "$PORT" -j NFQUEUE --queue-num 0
sudo iptables -D INPUT -i lo -p tcp --sport "$PORT" -j NFQUEUE --queue-num 0
kill "$(cat "$OUT/web.pid")" 2>/dev/null; docker rm -f ips >/dev/null 2>&1
grep '"event_type":"alert"' "$OUT/suricata/eve.json" 2>/dev/null | head -5 | cut -c1-400
if [ "$fails" -eq 0 ]; then echo "IPS OVERALL: PASS"; exit 0; else echo "IPS OVERALL: FAIL ($fails)"; exit 1; fi
