# Five-minute panel demo

Before the call (10 minutes ahead): double-click **start-demo.command** and wait for "Lab is ready".
Log in to the Wazuh dashboard (admin / SecretPassword). Have the Juice Shop tab open too.

| Step | Time | Do | Say |
|---|---|---|---|
| 1 | 0:00 | Show the README page on GitHub (architecture diagram). | "Three layers: a web application firewall in front of a vulnerable shop, intrusion detection watching the same traffic, and a SIEM collecting both." |
| 2 | 0:45 | Show Juice Shop in the browser; search for "apple". | "Normal traffic passes through the firewall untouched." |
| 3 | 1:30 | Double-click **attack-demo.command**. Point at the HTTP 403 lines. | "These are published attack patterns: SQL injection, cross-site scripting and a scan for sensitive files. The firewall blocks every one." |
| 4 | 2:30 | In the Wazuh tab that opens, click one alert to expand it. | "The SIEM received the firewall's block and Suricata's detection of the same attack, with the rule, source and MITRE ATT&CK technique." |
| 5 | 3:45 | Double-click **check-demo.command**; show the PASS lines. Then the scorecard on the README. | "The same checks run automatically on GitHub on every change; the scorecard and screenshots are from the latest green run." |

After the call: double-click **stop-demo.command** to free the memory.

If something is red: run **check-demo.command**, it names the failing part and the reason.
