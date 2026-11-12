#!/usr/bin/env bash
# EDR test (Linux runner): the runner itself is the endpoint. A Wazuh 4.9.2 agent watches it and
# reports to the lab's Wazuh manager. Four safe attacks taken from Atomic Red Team (pinned commit)
# run on the endpoint; each must raise an alert in the SIEM, and the time to alert is measured.
# Then an SSH brute force from a container must be detected AND the attacker's address cut off.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; . "$HERE/demo/lib.sh"
OUT="${OUT_DIR:-$PWD/out}/edr"; mkdir -p "$OUT"
ART="a0e3f9bc69fe"; AGENT="lab-endpoint"
TSV="$OUT/results.tsv"; : > "$TSV"; fails=0
rec() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$TSV"; printf '%-30s %-5s %6s  %s\n' "$1" "$2" "$3" "$4"; [ "$2" = PASS ] || fails=$((fails+1)); }

q_count() { alert_count "$1 AND agent.name:$AGENT"; }
wait_alert() { # query start_epoch limit -> prints seconds or "none"
  local q="$1" s="$2" lim="${3:-180}" n
  while :; do n=$(q_count "$q"); [ "$n" != error ] && [ "$n" -gt 0 ] 2>/dev/null && { echo $(( $(date +%s) - s )); return 0; }
    [ $(( $(date +%s) - s )) -ge "$lim" ] && { echo none; return 1; }; sleep 3; done; }

# Run one Atomic Red Team test by number, with its default inputs, exactly as written upstream.
atomic() { # technique index
  local t="$1" i="$2"
  curl -fsSL "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/$ART/atomics/$t/$t.yaml" -o "$OUT/$t.yaml" || return 1
  python3 - "$OUT/$t.yaml" "$i" > "$OUT/$t.$i.sh" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])); t = d["atomic_tests"][int(sys.argv[2])]
cmd = t["executor"]["command"]
for k, v in (t.get("input_arguments") or {}).items():
    cmd = cmd.replace("#{%s}" % k, str(v["default"]))
print("# %s: %s" % (d["attack_technique"], t["name"])); print(cmd)
PY
  echo "--- running $t #$i:"; cat "$OUT/$t.$i.sh"
  sudo bash "$OUT/$t.$i.sh" > "$OUT/$t.$i.out" 2>&1; echo "exit $?"
}

# 1. the endpoint is enrolled and reporting
n=$(curl -sk -m 10 -u "$API_USER:$API_PASS" -X POST "$API_URL/security/user/authenticate?raw=true")
st=$(curl -sk -m 10 -H "Authorization: Bearer $n" "$API_URL/agents?name=$AGENT" | python3 -c 'import sys,json;a=json.load(sys.stdin)["data"]["affected_items"];print(a[0]["status"] if a else "absent")' 2>/dev/null)
[ "$st" = active ] && rec endpoint_enrolled PASS "" "agent $AGENT is active in the Wazuh manager" || rec endpoint_enrolled FAIL "" "agent status: $st"

# 2-5. Atomic Red Team on the endpoint
run_case() { # name technique index query
  local s; s=$(date +%s); atomic "$2" "$3"
  local w; w=$(wait_alert "$4" "$s" 180)
  if [ "$w" = none ]; then rec "$1" FAIL "" "no alert for $2 within 180 s (query: $4)"
  else rec "$1" PASS "${w}s" "$2 detected: alert in the SIEM ${w} s after the attack"; fi
}
run_case atomic_T1136.001_new_user    T1136.001 0 'rule.id:5902'
run_case atomic_T1053.003_cron        T1053.003 2 'rule.groups:syscheck AND syscheck.path:*cron.d*'
run_case atomic_T1543.002_systemd     T1543.002 0 'rule.groups:syscheck AND syscheck.path:*systemd*'
run_case atomic_T1548.001_setuid      T1548.001 2 'rule.groups:syscheck AND syscheck.path:*evilBinary*'

# 6. SSH brute force from a container -> detected, then the attacker is cut off on the endpoint
HOSTIP=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
docker run -d --name attacker alpine:3.20 sleep 600 >/dev/null
docker exec attacker apk add -q openssh-client >/dev/null 2>&1
AIP=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' attacker)
s=$(date +%s)
for u in admin oracle test guest ftp backup support deploy postgres ubuntu; do
  docker exec attacker ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$u@$HOSTIP" true >/dev/null 2>&1
done
w=$(wait_alert 'rule.id:(5712 OR 5763)' "$s" 180)
[ "$w" = none ] && rec bruteforce_detected FAIL "" "no brute-force alert (5712/5763) within 180 s" \
  || rec bruteforce_detected PASS "${w}s" "SSH brute force from $AIP detected ${w} s after it started"
for i in $(seq 1 30); do sudo iptables -S 2>/dev/null | grep -q "$AIP" && break; sleep 2; done
if sudo iptables -S | grep -q "$AIP"; then
  if docker exec attacker sh -c "nc -z -w 5 $HOSTIP 22" >/dev/null 2>&1; then rec attacker_cut_off FAIL "" "drop rule present but port 22 still answers $AIP"
  else rec attacker_cut_off PASS "$(( $(date +%s) - s ))s" "active response added a DROP for $AIP; its next connection got no answer"; fi
else rec attacker_cut_off FAIL "" "no firewall rule for $AIP after the alert"; fi
sudo grep -h firewall-drop /var/ossec/logs/active-responses.log 2>/dev/null | tail -3
docker rm -f attacker >/dev/null 2>&1

if [ "$fails" -eq 0 ]; then echo "EDR OVERALL: PASS"; exit 0; else echo "EDR OVERALL: FAIL ($fails)"; exit 1; fi
