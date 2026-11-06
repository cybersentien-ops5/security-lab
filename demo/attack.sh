#!/usr/bin/env bash
# Sends published-pattern web attacks to the lab's Juice Shop (through the WAF) ONLY.
# Target is fixed to 127.0.0.1:8080, the lab's own WAF. Writes results to $OUT_DIR/attacks.tsv
set -u
. "$(dirname "$0")/lib.sh"
TSV="$OUT_DIR/attacks.tsv"
date +%s > "$OUT_DIR/attack_start"
printf 'category\tname\tmethod\tpath\thttp_status\n' > "$TSV"

send() { # category name method path [json-body]
  local code
  if [ "$3" = POST ]; then
    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data "$5" "$WAF_URL$4")
  else
    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' -g "$WAF_URL$4")
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$code" >> "$TSV"
  printf '  %-6s %-28s -> HTTP %s\n' "$1" "$2" "$code"
}

echo "Normal request (should be allowed):"
code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$WAF_URL/rest/products/search?q=apple")
echo "$code" > "$OUT_DIR/normal_status"; echo "  normal search -> HTTP $code"

echo "Attacks (should be blocked with HTTP 403):"
# SQL injection (OWASP Juice Shop's documented login and search injections)
send sqli login_or_1_equals_1   POST "/rest/user/login" '{"email":"'"'"' OR 1=1--","password":"lab"}'
send sqli search_union_select   GET  "/rest/products/search?q=%27))%20UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20Users--"
send sqli search_or_1_equals_1  GET  "/rest/products/search?q=%27%20OR%201=1--"
# Cross-site scripting
send xss  script_tag            GET  "/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
send xss  iframe_javascript     GET  "/rest/products/search?q=%3Ciframe%20src=%22javascript:alert(1)%22%3E"
send xss  img_onerror           GET  "/rest/products/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
# Directory scan for sensitive files (dirb / gobuster common-list entries)
for p in /.git/HEAD /.env /.htaccess /.svn/entries /wp-config.php.bak /backup.sql; do
  send scan "probe$p" GET "$p"
done

sent=$(($(wc -l < "$TSV") - 1)); blocked=$(awk -F'\t' 'NR>1 && $5==403' "$TSV" | wc -l | tr -d ' ')
echo "Sent $sent attacks, WAF blocked $blocked."
