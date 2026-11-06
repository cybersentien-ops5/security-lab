# Status (read this first after any restart)

Repo: https://github.com/cybersentien-ops5/security-lab  ·  Results of every CI run: branch `results`, folder `results/<run_id>/`

## Done
- Step 1: access confirmed (repo was empty on 2026-11-06).
- Lab files written: lab/compose.yml (Wazuh 4.9.2 single node, ModSecurity CRS 4.25.2 nginx + Juice Shop v17.1.1, Suricata 7.0.17 in the WAF namespace), demo/attack.sh, demo/check.sh, demo/lib.sh.
- Workflows: .github/workflows/lab-lite.yml (lab test), .github/workflows/secret-lint.yml (key/token scan).

## Next
- First lab-lite run on GitHub; read results branch; fix failures (max 3 attempts each).
- Laptop kit (.command files, demo/README.md), README with proof, docs/ROADMAP.md.

- Local sandbox dry run (not a GitHub run, own openssl certs because the sandbox cannot reach packages.wazuh.com): all 6 checks PASS, 12/12 attacks blocked, 12 WAF + 12 Suricata alerts in Wazuh, ~9 s to alert, 3 screenshots captured. Fixed two bugs it found (Juice Shop healthcheck node path; Suricata rules mount).
- Laptop kit written: demo/*.command, demo/README.md. README.md and docs/ROADMAP.md drafted.

## NOT VERIFIED
- Screenshots on GitHub (fix pushed after run 42177594699). The laptop (.command) files have not been run on a Mac.

## Runs
| Run id | Result | Notes |
|---|---|---|
| 42178189711 | FAIL | Suricata alerts 0 (af-packet capture saw no attack; flaky) and Playwright cannot install deps on the runner's Ubuntu 26.04. Fixes: Suricata libpcap capture + wait for 'Engine started' (Suricata attempt 1); screenshots in Playwright's pinned image (screenshot attempt 3, last). Both fixes verified in the local sandbox first. |
| 42177861433 | checks PASS, screenshots FAIL | 12/12 blocked, 7 s / 10 s to alert. Playwright 1.48 could not build on the runner's Python 3.14; moved to 1.56.0 (screenshot attempt 2). |
| 42177594699 | checks PASS, screenshots FAIL | 12/12 blocked, 12 WAF + 12 Suricata alerts, 7 s to alert. Screenshot step: pip refused (system Python); fixed with a venv (screenshot attempt 1). |
| 42176547097 | FAIL | certificate step: generator output hidden; likely root-owned cert folder unreadable by runner user. Fixed in lib.sh (attempt 1). |
