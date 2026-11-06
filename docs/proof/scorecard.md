# Scorecard - run 42179344856

Run: https://github.com/cybersentien-ops5/security-lab/actions/runs/42179344856

**Overall: PASS**

| Measure | Result |
|---|---|
| Attacks sent | 12 |
| Blocked by the WAF (HTTP 403) | 12 |
| WAF alerts in Wazuh | 12 |
| Suricata alerts in Wazuh | 12 |
| Seconds to first WAF alert | 6 |
| Seconds to first Suricata alert | 6 |

| Check | Result | Reason |
|---|---|---|
| containers_running | PASS | all 6 lab containers are running |
| waf_allows_normal_traffic | PASS | a normal product search returned HTTP 200 |
| waf_blocks_attacks | PASS | the WAF returned 403 for all 12 attacks |
| wazuh_has_waf_alert | PASS | Wazuh holds 12 WAF block alerts (rule 100101) |
| wazuh_has_ids_alert | PASS | Wazuh holds 12 Suricata alerts |
| dashboard_loads | PASS | the Wazuh dashboard login page returned HTTP 200 |

| Attack | Category | HTTP status |
|---|---|---|
| login_or_1_equals_1 | sqli | 403 |
| search_union_select | sqli | 403 |
| search_or_1_equals_1 | sqli | 403 |
| script_tag | xss | 403 |
| iframe_javascript | xss | 403 |
| img_onerror | xss | 403 |
| probe/.git/HEAD | scan | 403 |
| probe/.env | scan | 403 |
| probe/.htaccess | scan | 403 |
| probe/.svn/entries | scan | 403 |
| probe/wp-config.php.bak | scan | 403 |
| probe/backup.sql | scan | 403 |

Screenshots: blocked_request (captured), wazuh_overview (captured), alert_detail (captured)
