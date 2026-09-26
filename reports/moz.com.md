# Security Audit Report — moz.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://moz.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | moz.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H2 | Short HSTS max-age | CWE-319 |
| 5 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 6 | info | H2c | HSTS not preloaded | CWE-319 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://moz.com/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://moz.com/; no defense-in-depth against XSS/content injection.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for moz.com lists 1 name(s) besides the scope host: *.moz.com

### 4. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=2592000 (< 1 year): `max-age=2592000`.

### 5. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=2592000` does not cover subdomains.

### 6. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=2592000` lacks the preload directive.

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://moz.com/; browser features (camera, mic, geolocation) unrestricted.

### 8. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://moz.com/ lists 54 URLs.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://moz.com/ -> https://moz.com/ (positive check).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://moz.com/ exposes 21 unique Disallow path(s) (/admin-preview/*, /api/user?*, /blog/, /checkout/*, /community/q/questions/*/view_counts) and 2 sitemap reference(s)

### 11. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://moz.com (506 bytes); contact: inboundeng+cms@moz.com

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://moz.com/ final status: 200 (final URL https://moz.com/).
- http://moz.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-10T04:43:17+00:00.
