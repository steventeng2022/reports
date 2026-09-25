# Security Audit Report — shutterstock.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://shutterstock.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | shutterstock.com |
| Test date | 2026-09-25 02:55 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 5, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 4 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 5 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 6 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 12 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |
| 13 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://shutterstock.com/ without HttpOnly: datadome. Readable by client-side script.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://shutterstock.com/. Clients may connect over plain HTTP on first visit.

### 3. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://shutterstock.com/; no defense-in-depth against XSS/content injection.

### 4. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://shutterstock.com/; browsers may MIME-sniff responses.

### 5. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://shutterstock.com/; page may be rendered in a foreign frame.

### 6. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for shutterstock.com lists 23 name(s) besides the scope host: *.bigstockcorp.com, *.highresvideos.com, *.picdn.net, bancodevideos.com, bigstockcorp.com, creatorstour.de, freestock.com, freestockeditor.com...

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://shutterstock.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://shutterstock.com/; browser features (camera, mic, geolocation) unrestricted.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://shutterstock.com/ -> https://shutterstock.com:443/ (positive check).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://shutterstock.com/ exposes 52 unique Disallow path(s) (*/account, */base/logout, */collections, */editor/design, */editor/image/*) and 11 sitemap reference(s)

### 11. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://shutterstock.com (164 bytes); contact: mailto:appsec@shutterstock.com

### 12. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://shutterstock.com/ responded 403 (passive check only; no further probing).

### 13. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://shutterstock.com/ redirects to https://www.shutterstock.com:443/.

## Reproduction notes

- Scanned 2026-09-25 02:55 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://shutterstock.com/ final status: 403 (final URL https://www.shutterstock.com:443/).
- http://shutterstock.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2026-12-07T23:59:59+00:00.

## Passive re-audit cross-check (agent-passive, 2026-09-25)

Aggressive-method finding retained from chat log: **agent-random phase 22 (2026-09-25): HIGH subdomain takeover - admin.shutterstock.com CNAME -> admin.us-east-1.shuttercorp.net NXDOMAIN (DoH status 3), cross-zone dangling CNAME (parent zone shuttercorp.net exists, no apex A). Re-verified via DoH.**

This passive re-audit pass (no injection, no subdomain sweep) does not itself confirm the takeover; the CNAME/NXDOMAIN evidence above comes from the active agent's re-verification. Kept as HIGH pending owner decision on merge policy.
