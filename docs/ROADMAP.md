# Roadmap: from the lite lab to the full build

The lite lab is built so each item below is an addition, not a rework:
zones are already separate Docker networks (`dmz`, `app`, `siem`), every service carries
`lab.zone` / `lab.role` labels, custom Wazuh rules live in `lab/wazuh/config/lab_rules.xml`
(IDs 100100-100199 reserved for the lab), Suricata rules in `lab/suricata/lab.rules`
(SIDs 9000001-9000099), and every check writes one row to `cybersentien_export.json`.

In order:

1. **Network firewall between zones (nftables).** A small router container joins the three networks and enforces
   default-deny between `dmz`, `app` and `siem`; only WAF -> Juice Shop :3000 and log shipping are allowed. Its drop log is
   shipped to Wazuh like the WAF log, and the check adds "blocked cross-zone connection" rows.
2. **Certificates (step-ca).** A private certificate authority issues certificates for the WAF (HTTPS) and the Wazuh
   components, replacing the self-signed lab certificates. Check: certificate validity and expiry as export rows.
3. **Secure logins with MFA (Keycloak).** Keycloak provides single sign-on with TOTP for the Wazuh dashboard
   (OpenID Connect) and the shop's admin area. Failed and successful logins go to Wazuh.
4. **Data-leak detection of synthetic Tax File Numbers.** A Suricata/ModSecurity rule pair detects TFN-shaped numbers
   (with the TFN check-digit algorithm) leaving the shop; the test plants only synthetic, check-digit-valid fake TFNs.
5. **Automated response.** Wazuh active response blocks the attacking address at the WAF/router for a set time after
   repeated attack alerts; the check measures seconds from attack to block.
6. **Atomic Red Team attack simulation with an ATT&CK Navigator map.** Run selected Atomic tests inside a lab target
   container, record detected/not detected per technique, and publish a Navigator layer JSON in the results.
7. **CyberSentien connector on the TEST tenant `cybersentien-sandbox`.** Import `cybersentien_export.json`
   (one row per measured check: topic, state, detail, identity) into the sandbox tenant only.
8. **A link from cybersentien.com** to this lab's public README page.
