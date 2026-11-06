"""Copies a green run's scorecard and screenshots into README.md and docs/proof/.
Usage: update_readme.py <results/<run_id> dir>. Refuses a run whose overall result is not PASS."""
import json, shutil, sys, pathlib, re
src = pathlib.Path(sys.argv[1]); root = pathlib.Path(__file__).resolve().parents[1]
sc = json.loads((src / "scorecard.json").read_text())
if sc["overall"] != "PASS":
    sys.exit(f"run {sc['run_id']} is {sc['overall']}, not PASS: README not updated")
proof = root / "docs" / "proof"; shutil.rmtree(proof, ignore_errors=True); (proof / "screenshots").mkdir(parents=True)
for f in ["scorecard.md", "scorecard.json", "cybersentien_export.json"]:
    shutil.copy(src / f, proof / f)
shots = [p for p in sorted((src / "screenshots").glob("*.png")) if "problem" not in p.name]
for p in shots: shutil.copy(p, proof / "screenshots" / p.name)
rid, url = sc["run_id"], sc["run_url"]
titles = {"wazuh_overview": "Wazuh overview", "alert_detail": "One alert in detail (WAF block, rule 100101)",
          "blocked_request": "A blocked request (the firewall's HTTP 403)"}
L = ["## Latest results", "",
     f"From GitHub run [{rid}]({url}) (all checks passed). Full scorecard: [docs/proof/scorecard.md](docs/proof/scorecard.md) · "
     "[raw results for this run](../../tree/results/results/" + rid + ")", "",
     "| Measure | Result |", "|---|---|",
     f"| Attacks sent | {sc['attacks_sent']} |",
     f"| Blocked by the web application firewall | {sc['attacks_blocked']} of {sc['attacks_sent']} |",
     f"| Firewall alerts in the SIEM (Wazuh) | {sc['waf_alerts_in_wazuh']} |",
     f"| Suricata alerts in the SIEM (Wazuh) | {sc['suricata_alerts_in_wazuh']} |",
     f"| Seconds from first attack to alert in the SIEM | firewall {sc['seconds_to_waf_alert']} s · Suricata {sc['seconds_to_suricata_alert']} s |", ""]
for p in shots:
    t = titles.get(p.stem, p.stem.replace("_", " "))
    L += [f"**{t}**", "", f"![{t}](docs/proof/screenshots/{p.name})", ""]
readme = root / "README.md"; s = readme.read_text()
s = re.sub(r"<!-- SCORECARD:START -->.*<!-- SCORECARD:END -->",
           "<!-- SCORECARD:START -->\n" + "\n".join(L) + "\n<!-- SCORECARD:END -->", s, flags=re.S)
readme.write_text(s); print(f"README updated from run {rid}")
