"""Builds the public web page (GitHub Pages) from the newest green run's proof in docs/proof/.
Every number on the page is read from docs/proof/scorecard.json; nothing is typed in.
Usage: build_site.py <out_dir>"""
import html, json, shutil, sys, pathlib

root = pathlib.Path(__file__).resolve().parents[1]
proof = root / "docs" / "proof"
out = pathlib.Path(sys.argv[1]); shutil.rmtree(out, ignore_errors=True); (out / "img").mkdir(parents=True)
sc = json.loads((proof / "scorecard.json").read_text())
export = json.loads((proof / "cybersentien_export.json").read_text())
for p in (proof / "screenshots").glob("*.png"):
    shutil.copy(p, out / "img" / p.name)
(out / ".nojekyll").write_text("")
shutil.copy(proof / "cybersentien_export.json", out / "cybersentien_export.json")

e = html.escape
REPO = "https://github.com/cybersentien-ops5/security-lab"
rid, run_url = sc["run_id"], sc["run_url"]
names = {"containers_running": "All lab containers running", "waf_allows_normal_traffic": "Normal traffic still allowed",
         "waf_blocks_attacks": "Firewall blocks every attack", "wazuh_has_waf_alert": "Firewall alerts reach the SIEM",
         "wazuh_has_ids_alert": "Suricata alerts reach the SIEM", "dashboard_loads": "SIEM dashboard loads"}
checks = "".join(
    f'<li><span class="badge {"ok" if c["result"] == "PASS" else "bad"}">{e(c["result"])}</span>'
    f'<div><strong>{e(names.get(c["part"], c["part"]))}</strong><br><span class="muted">{e(c["reason"])}</span></div></li>'
    for c in sc["checks"])
crs = next((r["identity"] for r in export if r["topic"] == "waf_blocks_web_attacks"), "")
shots = [("blocked_request", "The firewall's answer to an attack", "A cross-site scripting attempt sent from a browser gets HTTP 403 Forbidden from the web application firewall."),
         ("alert_detail", "One alert, opened in the SIEM", "Wazuh shows the firewall's block as an alert (rule 100101, level 10) with the source, the request and the MITRE ATT&CK technique T1190."),
         ("wazuh_overview", "The SIEM overview", "Wazuh's dashboard home after the attack, with the alert counts by severity.")]
topic_names = {"lab_containers_running": "Lab services running", "waf_allows_legitimate_traffic": "Legitimate traffic allowed",
               "waf_blocks_web_attacks": "Web attacks blocked", "siem_receives_waf_alerts": "Firewall alerts reach the SIEM",
               "ids_detects_attacks_in_siem": "Intrusion detection alerts reach the SIEM", "siem_dashboard_available": "SIEM dashboard available",
               "time_to_detect": "Time to detect"}
state_cls = {"met": "ok", "gap": "bad", "collected": "info"}
evidence = "".join(
    f'<tr><td><strong>{e(topic_names.get(r["topic"], r["topic"]))}</strong><br><code>{e(r["topic"])}</code></td>'
    f'<td><span class="badge {state_cls.get(r["state"], "info")}">{e(r["state"])}</span></td>'
    f'<td>{e(r["detail"])}<br><span class="muted small">{e(r["identity"][:140])}</span></td></tr>'
    for r in export)
gallery = "".join(
    f'<figure><a href="img/{k}.png"><img src="img/{k}.png" alt="{e(t)}" loading="lazy"></a>'
    f'<figcaption><strong>{e(t)}</strong><br>{e(d)}</figcaption></figure>'
    for k, t, d in shots if (out / "img" / f"{k}.png").exists())

page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Lab · Aneis Samaan</title>
<meta name="description" content="A security lab showing a web application firewall, intrusion detection and a SIEM catching a simulated attack, with proof from an automated test run.">
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#14181f;--muted:#5b6472;--line:#e3e6eb;--accent:#1f5eff;--ok:#0f7b45;--okbg:#e5f5ec;--bad:#b42318;--badbg:#fdecea;--waf:#7a3cff;--ids:#d9480f;--siem:#1f5eff;--app:#0f7b45}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--bg:#0f1217;--card:#171b22;--ink:#e8ebf0;--muted:#9aa3b2;--line:#2a303a;--accent:#6c95ff;--ok:#4cc38a;--okbg:#14301f;--bad:#ff8a80;--badbg:#3a1714;--waf:#a98bff;--ids:#ff9a62;--siem:#6c95ff;--app:#4cc38a}}}}
:root[data-theme="dark"]{{--bg:#0f1217;--card:#171b22;--ink:#e8ebf0;--muted:#9aa3b2;--line:#2a303a;--accent:#6c95ff;--ok:#4cc38a;--okbg:#14301f;--bad:#ff8a80;--badbg:#3a1714;--waf:#a98bff;--ids:#ff9a62;--siem:#6c95ff;--app:#4cc38a}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
a{{color:var(--accent)}} .wrap{{max-width:1080px;margin:0 auto;padding:0 16px}}
header{{padding:48px 0 24px}} h1{{font-size:clamp(28px,4vw,40px);line-height:1.15;margin:0 0 10px}} h2{{font-size:22px;margin:0 0 14px}}
.lead{{font-size:18px;color:var(--muted);max-width:760px;margin:0}} .by{{margin-top:14px;font-weight:600}}
section{{margin:28px 0}} .card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px}}
.grid3{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}}
.layer h3{{margin:0 0 6px;font-size:17px}} .layer p{{margin:0;color:var(--muted)}} .dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}} .tile .n{{font-size:32px;font-weight:700;line-height:1.1}} .tile .l{{color:var(--muted);font-size:14px}}
.pass{{display:inline-flex;align-items:center;gap:8px;background:var(--okbg);color:var(--ok);font-weight:700;border-radius:999px;padding:6px 14px}}
ul.checks{{list-style:none;padding:0;margin:0;display:grid;gap:10px}} ul.checks li{{display:flex;gap:12px;align-items:flex-start}}
.badge{{font-size:12px;font-weight:700;border-radius:6px;padding:3px 8px;flex:none;margin-top:2px}} .badge.ok{{background:var(--okbg);color:var(--ok)}} .badge.bad{{background:var(--badbg);color:var(--bad)}} .badge.info{{background:var(--bg);color:var(--accent);border:1px solid var(--line)}}
table.ev{{width:100%;border-collapse:collapse;font-size:14px}} table.ev td{{border-top:1px solid var(--line);padding:10px 8px;vertical-align:top}} table.ev td:first-child{{width:30%}} table.ev td:nth-child(2){{width:90px}}
.flow{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:4px 0 16px}} .flow span{{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:6px 10px;font-size:14px}} .flow b{{color:var(--muted)}}
.tablewrap{{overflow-x:auto}}
.muted{{color:var(--muted)}} .small{{font-size:14px}}
figure{{margin:0;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}} figure img{{display:block;width:100%;height:auto;border-bottom:1px solid var(--line)}} figcaption{{padding:12px 14px;font-size:14px;color:var(--muted)}} figcaption strong{{color:var(--ink)}}
.gallery{{display:grid;grid-template-columns:1fr;gap:18px;max-width:980px}}
svg text{{fill:var(--ink);font:13px system-ui,sans-serif}} svg .sub{{fill:var(--muted);font-size:11px}} svg .box{{fill:var(--card);stroke-width:2}} svg .zone{{fill:none;stroke:var(--line);stroke-dasharray:5 4}} svg .zl{{fill:var(--muted);font-size:11px;letter-spacing:.06em}} svg .arrow{{stroke:var(--muted);stroke-width:1.6;fill:none;marker-end:url(#ah)}}
.diagram{{overflow-x:auto}} ol.steps{{margin:0;padding-left:20px}} ol.steps li{{margin:6px 0}} code{{background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:14px}}
footer{{padding:30px 0 50px;color:var(--muted);font-size:14px}}
</style></head><body>
<div class="wrap">
<header>
  <h1>Security Lab: catching a web attack three ways</h1>
  <p class="lead">A web application firewall, intrusion detection and a SIEM working together on a deliberately vulnerable web shop. A scripted attack is sent, the firewall blocks it, and the SIEM shows the firewall and Suricata alerts within seconds.</p>
  <div class="by">Aneis Samaan · <a href="https://cybersentien.com">CyberSentien</a></div>
</header>

<section class="tiles" aria-label="Latest results">
  <div class="tile"><div class="n">{sc['attacks_blocked']}/{sc['attacks_sent']}</div><div class="l">attacks blocked by the firewall</div></div>
  <div class="tile"><div class="n">{sc['waf_alerts_in_wazuh']}</div><div class="l">firewall alerts in the SIEM</div></div>
  <div class="tile"><div class="n">{sc['suricata_alerts_in_wazuh']}</div><div class="l">intrusion detection alerts in the SIEM</div></div>
  <div class="tile"><div class="n">{sc['seconds_to_waf_alert']} s</div><div class="l">from first attack to alert in the SIEM</div></div>
</section>
<p class="small muted">Measured by automated test run <a href="{e(run_url)}">{e(rid)}</a> on GitHub. All data is synthetic and the attacks only target the lab's own containers.</p>

<section class="grid3">
  <div class="card layer"><h3><span class="dot" style="background:var(--waf)"></span>Web application firewall</h3><p>ModSecurity with the OWASP Core Rule Set in blocking mode, in front of OWASP Juice Shop. Malicious requests get HTTP 403 before they reach the shop.</p></div>
  <div class="card layer"><h3><span class="dot" style="background:var(--ids)"></span>Intrusion detection</h3><p>Suricata watches the same network interface as the firewall and raises its own alert for each attack pattern it recognises.</p></div>
  <div class="card layer"><h3><span class="dot" style="background:var(--siem)"></span>SIEM</h3><p>Wazuh collects both logs, applies detection rules mapped to MITRE ATT&amp;CK, and shows the alerts on one dashboard.</p></div>
</section>

<section class="card">
  <h2>How it fits together</h2>
  <div class="diagram">
  <svg viewBox="0 0 980 300" width="100%" style="min-width:720px" role="img" aria-label="Architecture: attacker to firewall to Juice Shop; Suricata watches the firewall; both send logs to Wazuh">
    <defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" style="color:var(--muted)"/></marker></defs>
    <rect class="zone" x="190" y="20" width="270" height="260" rx="12"/><text class="zl" x="205" y="40">DMZ ZONE</text>
    <rect class="zone" x="500" y="20" width="200" height="110" rx="12"/><text class="zl" x="515" y="40">APP ZONE</text>
    <rect class="zone" x="500" y="150" width="460" height="130" rx="12"/><text class="zl" x="515" y="170">SIEM ZONE</text>
    <rect class="box" x="20" y="70" width="140" height="60" rx="10" style="stroke:var(--bad)"/><text x="38" y="96">Attack script</text><text class="sub" x="38" y="114">SQLi · XSS · file scan</text>
    <rect class="box" x="215" y="60" width="220" height="70" rx="10" style="stroke:var(--waf)"/><text x="232" y="88">Web application firewall</text><text class="sub" x="232" y="108">ModSecurity + OWASP CRS, blocking</text>
    <rect class="box" x="215" y="190" width="220" height="60" rx="10" style="stroke:var(--ids)"/><text x="232" y="216">Suricata IDS</text><text class="sub" x="232" y="234">same network interface</text>
    <rect class="box" x="525" y="55" width="150" height="60" rx="10" style="stroke:var(--app)"/><text x="542" y="82">OWASP Juice Shop</text><text class="sub" x="542" y="100">vulnerable web shop</text>
    <rect class="box" x="525" y="190" width="125" height="60" rx="10" style="stroke:var(--siem)"/><text x="540" y="216">Wazuh manager</text><text class="sub" x="540" y="234">rules + alerts</text>
    <rect class="box" x="680" y="190" width="125" height="60" rx="10" style="stroke:var(--siem)"/><text x="695" y="216">Wazuh indexer</text><text class="sub" x="695" y="234">stores alerts</text>
    <rect class="box" x="835" y="190" width="110" height="60" rx="10" style="stroke:var(--siem)"/><text x="848" y="216">Dashboard</text><text class="sub" x="848" y="234">what you see</text>
    <path class="arrow" d="M160 100 H213"/><text class="sub" x="166" y="92">HTTP</text>
    <path class="arrow" d="M435 85 H523"/><text class="sub" x="445" y="77">allowed only</text>
    <path class="arrow" d="M325 188 V132" style="stroke-dasharray:4 3"/><text class="sub" x="332" y="165">watches</text>
    <path class="arrow" d="M435 115 C480 115 480 205 523 205"/><text class="sub" x="440" y="148">firewall log</text>
    <path class="arrow" d="M435 225 H523"/><text class="sub" x="447" y="217">eve.json</text>
    <path class="arrow" d="M650 220 H678"/><path class="arrow" d="M805 220 H833"/>
  </svg></div>
  <p class="small muted">The zones are separate networks, so a zone firewall, single sign-on with MFA and automated response can be added later without rebuilding anything.</p>
</section>

<section class="card">
  <h2>What the automated test proved <span class="pass">{e(sc['overall'])}</span></h2>
  <ul class="checks">{checks}</ul>
  <p class="small muted" style="margin-top:14px">Firewall rules that fired: {e(crs.replace('OWASP CRS rules ', ''))}. Machine-readable results: <a href="cybersentien_export.json">cybersentien_export.json</a>.</p>
</section>

<section class="card">
  <h2>How the lab feeds CyberSentien</h2>
  <p class="muted" style="margin-top:0">Every check the lab runs becomes an evidence row in the format the CyberSentien readiness engine reads: what was checked, whether it is met or a gap, the measured figure, and the exact rule, alert or container that proves it. Only measured results become rows.</p>
  <div class="flow"><span>Simulated attack</span><b>&rarr;</b><span>Firewall, IDS and SIEM checks</span><b>&rarr;</b><span>Evidence rows (<a href="cybersentien_export.json">JSON</a>)</span><b>&rarr;</b><span>CyberSentien test tenant (next step)</span></div>
  <div class="tablewrap"><table class="ev"><tbody>{evidence}</tbody></table></div>
  <p class="small muted" style="margin-bottom:0">From run {e(rid)}. Importing these rows into CyberSentien's test tenant is the next step of the build and is not live yet.</p>
</section>

<section>
  <h2>Screenshots from that run</h2>
  <div class="gallery">{gallery}</div>
</section>

<section class="card">
  <h2>Run it yourself</h2>
  <ol class="steps">
    <li>Install Docker Desktop and give it at least 6 GB of memory.</li>
    <li><code>git clone {REPO}.git</code></li>
    <li>In the <code>demo</code> folder, double-click <code>start-demo.command</code>, then <code>attack-demo.command</code>.</li>
    <li><code>check-demo.command</code> prints PASS or FAIL for each part; <code>stop-demo.command</code> frees the memory.</li>
  </ol>
  <p class="small muted">Pinned versions: Wazuh 4.9.2 · OWASP ModSecurity CRS 4.25.2 · OWASP Juice Shop 17.1.1 · Suricata 7.0.17. Source code and every test run: <a href="{REPO}">{REPO.replace('https://', '')}</a>.</p>
</section>

<footer>Built by Aneis Samaan, <a href="https://cybersentien.com">CyberSentien</a>. Lab only: synthetic data, attacks confined to the lab's own containers.</footer>
</div></body></html>
"""
(out / "index.html").write_text(page)
print(f"site built from run {rid} -> {out}")
