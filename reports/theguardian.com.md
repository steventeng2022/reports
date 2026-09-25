# Security Audit Report — theguardian.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://theguardian.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | theguardian.com |
| Test date | 2026-09-25 13:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 3, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://theguardian.com/ without HttpOnly: GU_geo_country, GU_mvt_id, gu_client_ab_tests, gu_v2_mvt_id. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://theguardian.com/ without Secure: gu_client_ab_tests, gu_v2_mvt_id. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://theguardian.com/ without SameSite=Lax/Strict: GU_geo_country, GU_mvt_id, gu_client_ab_tests, gu_v2_mvt_id. Cross-site request cookies.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for theguardian.com lists 32 name(s) besides the scope host: *.code.dev-guardianapis.com, *.code.dev-theguardian.com, *.dev-theguardian.com, *.editorial.theguardian.com, *.email.theguardian.com, *.guardian.co.uk, *.guardianapis.com, *.guim.co.uk...

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://theguardian.com/ -> https://theguardian.com/ (positive check).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://theguardian.com/ exposes 49 unique Disallow path(s) (*.emailjson, *.emailtxt, *?*dcr=apps*, /, /*/feedarticle/*) and 2 sitemap reference(s)

### 7. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://theguardian.com (203 bytes); contact: mailto:appsec@theguardian.com

## Reproduction notes

- Scanned 2026-09-25 13:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://theguardian.com/ final status: 200 (final URL https://www.theguardian.com/international).
- http://theguardian.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign Atlas R46 DV TLS CA 2026 Q3, valid until 2027-03-05T10:24:58+00:00.
