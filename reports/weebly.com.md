# Security Audit Report — weebly.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://weebly.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | weebly.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 6, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 6 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 7 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 8 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 14 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://weebly.com/ without HttpOnly: _csrf, cookie-consent, external_paid_signup_referer, external_signup_referer, internal_signup_referer, language, srv_domainuserid, wcid, wct-aG9tZXBhZ2Vfd2Vic2l0ZV9tZXNzYWdpbmdfdjU_, wct-bG9jYWxlTmV3VXNlckNoYXQ_, wct-c2lnbnVwX21haWxjaGVja19hbGxlbmc_, wtp-uuid. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://weebly.com/ without Secure: _csrf, cookie-consent, external_paid_signup_referer, external_signup_referer, internal_signup_referer, language, srv_domainuserid, wcid, wct-aG9tZXBhZ2Vfd2Vic2l0ZV9tZXNzYWdpbmdfdjU_, wct-bG9jYWxlTmV3VXNlckNoYXQ_, wct-c2lnbnVwX21haWxjaGVja19hbGxlbmc_, wtp-uuid. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://weebly.com/ without SameSite=Lax/Strict: _csrf, cookie-consent, external_paid_signup_referer, external_signup_referer, internal_signup_referer, language, srv_domainuserid, wcid, wct-aG9tZXBhZ2Vfd2Vic2l0ZV9tZXNzYWdpbmdfdjU_, wct-bG9jYWxlTmV3VXNlckNoYXQ_, wct-c2lnbnVwX21haWxjaGVja19hbGxlbmc_, wtp-uuid. Cross-site request cookies.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://weebly.com/. Clients may connect over plain HTTP on first visit.

### 5. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://weebly.com/; no defense-in-depth against XSS/content injection.

### 6. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://weebly.com/; browsers may MIME-sniff responses.

### 7. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond weebly.com: www.weebly.com.

### 8. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for weebly.com lists 1 name(s) besides the scope host: *.weebly.com

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://weebly.com/; full URL (incl. query strings) is sent as referrer by default.

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://weebly.com/; browser features (camera, mic, geolocation) unrestricted.

### 11. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://weebly.com/ lists 1240 URLs.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://weebly.com/ -> https://www.weebly.com/ (positive check).

### 13. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://weebly.com/ exposes 21 unique Disallow path(s) (/, /app-center/oauth/authorize, /choose-a-plan/, /data-processing-terms/, /designer_pricing.php) and 1 sitemap reference(s)

### 14. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on weebly.com.

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://weebly.com/ final status: 200 (final URL https://www.weebly.com/).
- http://weebly.com/ initial status: 302.
- Certificate: Let's Encrypt YE2, valid until 2026-11-06T20:20:53+00:00.

## Passive re-audit cross-check (agent-passive, 2026-09-25)

Aggressive-method finding retained from chat log: **agent-random phase 22 (2026-09-25): HIGH subdomain takeover - dev.weebly.com CNAME -> weebly.github.io, backing GitHub repo 404 (dangling GitHub Pages). Re-verified via DoH.**

This passive re-audit pass (no injection, no subdomain sweep) does not itself confirm the takeover; the CNAME/NXDOMAIN evidence above comes from the active agent's re-verification. Kept as HIGH pending owner decision on merge policy.

## Active agent cross-check (latest aggressive scan on main, wave 5 - weebly.com)

Total findings: **19** - latest aggressive-method scan by agent-aggressive (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | B9 | Subdomain takeover candidate (dangling GitHub Pages CNAME) | CWE-1596 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C1 | Cookie without Secure flag | CWE-614 |
| 4 | low | C1 | Cookie without Secure flag | CWE-614 |
| 5 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 6 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 7 | low | H1 | Missing HSTS header | CWE-319 |
| 8 | low | H1 | Missing HSTS header | CWE-319 |
| 9 | low | H2 | Missing CSP header | CWE-1021 |
| 10 | low | H2 | Missing CSP header | CWE-1021 |
| 11 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 12 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 13 | low | H4 | No clickjacking protection | CWE-1023 |
| 14 | low | H4 | No clickjacking protection | CWE-1023 |
| 15 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 16 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 17 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 18 | info | H6 | Server technology disclosure | CWE-200 |
| 19 | info | H6 | Server technology disclosure | CWE-200 |
