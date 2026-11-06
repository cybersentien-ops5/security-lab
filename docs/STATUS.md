# Status (read this first after any restart)

Repo: https://github.com/cybersentien-ops5/security-lab  ·  Results of every CI run: branch `results`, folder `results/<run_id>/`

## Done
- Lab (lab/compose.yml): Wazuh 4.9.2 single node (certs from Wazuh's own generator), ModSecurity CRS 4.25.2 nginx in blocking mode in front of Juice Shop v17.1.1, Suricata 7.0.17 in the WAF's network namespace (libpcap capture). WAF audit log and Suricata eve.json shipped to Wazuh through shared read-only volumes.
- demo/attack.sh (12 published-pattern attacks: 3 SQL injection, 3 XSS, 6 sensitive-file probes), demo/check.sh, demo/lib.sh.
- CI: .github/workflows/lab-lite.yml, .github/workflows/secret-lint.yml.
- **Green run 42179344856** (commit c756ee8): all 6 checks PASS, 12/12 attacks blocked (HTTP 403), 12 WAF + 12 Suricata alerts in Wazuh, 6 s to first alert for both, 3 screenshots captured. README "Latest results" and docs/proof/ copied from this run.
- Laptop kit: demo/start-demo.command, attack-demo.command, check-demo.command, stop-demo.command, demo/README.md (5-step panel script).
- docs/ROADMAP.md for the full build.

## Next
- Nothing required. Optional: run the kit on the Mac once before the interview.

## NOT VERIFIED
- The four .command files have not been run on a Mac (no Mac test possible from here). The lab itself is proven on GitHub's Linux runner; the Mac uses the same compose file and scripts.

## Runs
| Run id | Result | Notes |
|---|---|---|
| 42179344856 | **PASS** | all checks and screenshots; 6 s to alert |
| 42178189711 | FAIL | Suricata 0 alerts (af-packet) and Playwright deps on Ubuntu 26.04; fixed (libpcap + readiness wait; Playwright's pinned image) |
| 42177861433 | checks PASS, screenshots FAIL | Playwright 1.48 would not build on Python 3.14 |
| 42177594699 | checks PASS, screenshots FAIL | pip refused system Python |
| 42176547097 | FAIL | certificate folder unreadable by the runner user; fixed in lib.sh |
