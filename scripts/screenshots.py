"""Playwright screenshots for the scorecard: Wazuh overview, one alert detail, one blocked request.
Writes PNGs and screenshots.json (what each shot shows and whether it was captured) to argv[1]."""
import json, sys, time, urllib.parse, pathlib
from playwright.sync_api import sync_playwright

out = pathlib.Path(sys.argv[1]); shots = out / "screenshots"; shots.mkdir(parents=True, exist_ok=True)
WAF = "http://127.0.0.1:8080"; DASH = "https://127.0.0.1:8443"
report = {}

def note(name, ok, detail):
    report[name] = {"captured": ok, "detail": detail}
    print(f"{name}: {'captured' if ok else 'NOT captured'} - {detail}")

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()

    # 1. blocked request (the WAF's real 403 answer to an XSS attempt)
    try:
        url = WAF + "/rest/products/search?q=" + urllib.parse.quote("<script>alert(1)</script>")
        r = pg.goto(url, timeout=30000)
        pg.screenshot(path=str(shots / "blocked_request.png"))
        note("blocked_request", True, f"browser request {url} answered HTTP {r.status if r else 'none'}")
    except Exception as e:
        note("blocked_request", False, repr(e)[:300])

    # log in to the Wazuh dashboard
    logged_in = False
    try:
        pg.goto(DASH + "/app/login", timeout=60000)
        pg.wait_for_selector('input[data-test-subj="user-name"]', timeout=60000)
        pg.fill('input[data-test-subj="user-name"]', "admin")
        pg.fill('input[data-test-subj="password"]', "SecretPassword")
        pg.click('button[data-test-subj="submit"]')
        pg.wait_for_url(lambda u: "/app/login" not in u, timeout=60000)
        logged_in = True
    except Exception as e:
        note("dashboard_login", False, repr(e)[:300])
        try: pg.screenshot(path=str(shots / "dashboard_login_problem.png"))
        except Exception: pass

    # 2. Wazuh overview
    if logged_in:
        try:
            pg.goto(DASH + "/app/wz-home", timeout=60000)
            pg.wait_for_load_state("networkidle", timeout=60000)
            time.sleep(10)
            pg.screenshot(path=str(shots / "wazuh_overview.png"))
            note("wazuh_overview", True, "Wazuh dashboard home after login")
        except Exception as e:
            note("wazuh_overview", False, repr(e)[:300])

    # 3. one alert detail (Discover on wazuh-alerts-*, WAF block rule, first row expanded)
    if logged_in:
        try:
            q = urllib.parse.quote("rule.id:100101")
            url = (DASH + "/app/data-explorer/discover#?_a=(discover:(columns:!(_source),isDirty:!f,sort:!()),"
                   "metadata:(indexPattern:'wazuh-alerts-*',view:discover))&_g=(time:(from:now-1h,to:now))"
                   f"&_q=(filters:!(),query:(language:kuery,query:'{q}'))")
            pg.goto(url, timeout=60000)
            pg.wait_for_load_state("networkidle", timeout=60000)
            time.sleep(8)
            expanded = False
            for sel in ['button[aria-label="Toggle row details"]', '[data-test-subj="docTableExpandToggleColumn"] button',
                        'button[aria-label="Inspect document details"]']:
                if pg.locator(sel).count():
                    pg.locator(sel).first.click(); time.sleep(4); expanded = True; break
            pg.screenshot(path=str(shots / "alert_detail.png"))
            note("alert_detail", True, "Discover, query rule.id:100101" + (", first alert expanded" if expanded else ", row list (expand control not found)"))
        except Exception as e:
            note("alert_detail", False, repr(e)[:300])
    b.close()

(out / "screenshots.json").write_text(json.dumps(report, indent=2))
