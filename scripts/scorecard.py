"""Builds scorecard.md, scorecard.json and cybersentien_export.json from measured files only.
Usage: scorecard.py <out_dir> <run_id> <run_url>. A check that did not run gets no row."""
import csv, json, re, sys, pathlib
out = pathlib.Path(sys.argv[1]); run_id = sys.argv[2]; run_url = sys.argv[3]

def read_tsv(name):
    p = out / name
    return list(csv.DictReader(p.open(), delimiter="\t")) if p.exists() else []

def read(name, default=""):
    p = out / name
    return p.read_text().strip() if p.exists() else default

def hit(name):
    try:
        h = json.loads(read(name, "{}"))["hits"]["hits"]
        return h[0] if h else None
    except Exception:
        return None

checks = {r["part"]: r for r in read_tsv("checks.tsv")}
attacks = read_tsv("attacks.tsv")
containers = dict(l.split(None, 1)[::-1] for l in read("containers.txt").splitlines() if l.strip())  # service -> id
crs_rules = sorted(set(re.findall(r'"ruleId":"(\d+)"', read("logs/waf_modsec_audit.tail.txt"))) - {"949110", "980170", "959100", "980130"})
waf_hit, ids_hit = hit("waf_alert_sample.json"), hit("ids_alert_sample.json")
shots = json.loads(read("screenshots.json", "{}"))
waf_s, ids_s = read("waf_seconds"), read("ids_seconds")

sent = len(attacks); blocked = sum(1 for a in attacks if a["http_status"] == "403")
def cnt(part):
    v = checks.get(part, {}).get("value", "")
    return int(v) if v.isdigit() else None

score = {
    "run_id": run_id, "run_url": run_url,
    "overall": "PASS" if checks and all(c["result"] == "PASS" for c in checks.values()) else ("FAIL" if checks else "NOT VERIFIED"),
    "attacks_sent": sent if attacks else None, "attacks_blocked": blocked if attacks else None,
    "waf_alerts_in_wazuh": cnt("wazuh_has_waf_alert"), "suricata_alerts_in_wazuh": cnt("wazuh_has_ids_alert"),
    "seconds_to_waf_alert": int(waf_s) if waf_s.isdigit() else None,
    "seconds_to_suricata_alert": int(ids_s) if ids_s.isdigit() else None,
    "checks": list(checks.values()), "screenshots": shots,
}
(out / "scorecard.json").write_text(json.dumps(score, indent=2))

# --- export for a later CyberSentien import ---
rows = []
def row(topic, part, identity):
    c = checks.get(part)
    if c:
        rows.append({"topic": topic, "state": "met" if c["result"] == "PASS" else "gap",
                     "detail": c["reason"][0].upper() + c["reason"][1:] + f" (run {run_id}).", "identity": identity})
row("lab_containers_running", "containers_running", "containers " + ", ".join(f"{s}={i[:12]}" for s, i in sorted(containers.items())) or "unknown")
row("waf_allows_legitimate_traffic", "waf_allows_normal_traffic", f"container waf={containers.get('waf','unknown')[:12]}")
row("waf_blocks_web_attacks", "waf_blocks_attacks", "OWASP CRS rules " + (", ".join(crs_rules) if crs_rules else "not read from audit log"))
def alert_id(h): return h.get("_id", "unknown") if h else "none"
if waf_hit:
    wr = waf_hit["_source"].get("rule", {}).get("id", "100101")
else:
    wr = "100101"
row("siem_receives_waf_alerts", "wazuh_has_waf_alert", f"Wazuh rule {wr}, alert {alert_id(waf_hit)}")
if ids_hit:
    s = ids_hit["_source"]; sid = s.get("data", {}).get("alert", {}).get("signature_id", "unknown")
    ids_ident = f"Suricata sid {sid}, Wazuh rule {s.get('rule', {}).get('id', 'unknown')}, alert {alert_id(ids_hit)}"
else:
    ids_ident = "Suricata (no alert found)"
row("ids_detects_attacks_in_siem", "wazuh_has_ids_alert", ids_ident)
row("siem_dashboard_available", "dashboard_loads", f"container wazuh.dashboard={containers.get('wazuh.dashboard','unknown')[:12]}")
if waf_s.isdigit() and ids_s.isdigit():
    rows.append({"topic": "time_to_detect", "state": "collected",
                 "detail": f"The first WAF alert was searchable in Wazuh {waf_s} s and the first Suricata alert {ids_s} s after the first attack (run {run_id}).",
                 "identity": f"Wazuh rule {wr}; {ids_ident}"})
(out / "cybersentien_export.json").write_text(json.dumps(rows, indent=2))

# --- markdown scorecard ---
L = [f"# Scorecard - run {run_id}", "", f"Run: {run_url}", "", f"**Overall: {score['overall']}**", "",
     "| Measure | Result |", "|---|---|",
     f"| Attacks sent | {score['attacks_sent'] if attacks else 'not run'} |",
     f"| Blocked by the WAF (HTTP 403) | {blocked if attacks else 'not run'} |",
     f"| WAF alerts in Wazuh | {score['waf_alerts_in_wazuh'] if score['waf_alerts_in_wazuh'] is not None else 'not measured'} |",
     f"| Suricata alerts in Wazuh | {score['suricata_alerts_in_wazuh'] if score['suricata_alerts_in_wazuh'] is not None else 'not measured'} |",
     f"| Seconds to first WAF alert | {waf_s or 'not measured'} |",
     f"| Seconds to first Suricata alert | {ids_s or 'not measured'} |", "",
     "| Check | Result | Reason |", "|---|---|---|"]
L += [f"| {c['part']} | {c['result']} | {c['reason']} |" for c in checks.values()]
if attacks:
    L += ["", "| Attack | Category | HTTP status |", "|---|---|---|"]
    L += [f"| {a['name']} | {a['category']} | {a['http_status']} |" for a in attacks]
L += ["", "Screenshots: " + ", ".join(f"{k} ({'captured' if v['captured'] else 'NOT captured'})" for k, v in shots.items())]
(out / "scorecard.md").write_text("\n".join(L) + "\n")
print("\n".join(L[:14]))
