# Status (read this first after any restart)

Repo: https://github.com/cybersentien-ops5/security-lab  ·  Results of every CI run: branch `results`, folder `results/<run_id>/`

## Done
- Step 1: access confirmed (repo was empty on 2026-11-06).
- Lab files written: lab/compose.yml (Wazuh 4.9.2 single node, ModSecurity CRS 4.25.2 nginx + Juice Shop v17.1.1, Suricata 7.0.17 in the WAF namespace), demo/attack.sh, demo/check.sh, demo/lib.sh.
- Workflows: .github/workflows/lab-lite.yml (lab test), .github/workflows/secret-lint.yml (key/token scan).

## Next
- First lab-lite run on GitHub; read results branch; fix failures (max 3 attempts each).
- Laptop kit (.command files, demo/README.md), README with proof, docs/ROADMAP.md.

## NOT VERIFIED
- Everything: no lab-lite run has completed yet.

## Runs
| Run id | Result | Notes |
|---|---|---|
