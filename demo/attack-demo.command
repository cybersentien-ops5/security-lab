#!/usr/bin/env bash
# Double-click to send the simulated attacks and open the Wazuh alerts view.
cd "$(dirname "$0")" || exit 1
. ./lib.sh
echo "=== Security lab: simulated attack (targets only the lab's own Juice Shop) ==="
bash ./attack.sh
echo
echo "Waiting for the alerts to reach Wazuh..."
for i in $(seq 1 40); do
  w=$(alert_count "$WAF_ALERT_Q"); s=$(alert_count "$IDS_ALERT_Q")
  if [ "$w" != error ] && [ "$s" != error ] && [ "$w" -ge 1 ] && [ "$s" -ge 1 ]; then break; fi
  sleep 3
done
echo "Wazuh now holds: WAF block alerts = $w, Suricata alerts = $s"
open "$DASH_URL/app/data-explorer/discover#?_a=(discover:(columns:!(rule.description,rule.id,agent.name),isDirty:!f,sort:!()),metadata:(indexPattern:'wazuh-alerts-*',view:discover))&_g=(time:(from:now-1h,to:now))&_q=(filters:!(),query:(language:kuery,query:'rule.groups:waf%20or%20rule.groups:suricata'))"
read -r -p "Press Enter to close." _
