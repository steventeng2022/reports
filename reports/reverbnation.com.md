# Security Audit Report — reverbnation.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://reverbnation.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | reverbnation.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://reverbnation.com/ without HttpOnly: ahoy_track, ahoy_visit, ahoy_visitor. Readable by client-side script.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://reverbnation.com/; no defense-in-depth against XSS/content injection.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for reverbnation.com lists 1 name(s) besides the scope host: *.reverbnation.com

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=63072000; includeSubDomains` lacks the preload directive.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://reverbnation.com/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://reverbnation.com/ lists 0 URLs.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://reverbnation.com/ -> https://reverbnation.com/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://reverbnation.com/ exposes 0 unique Disallow path(s)

### 9. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on reverbnation.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://reverbnation.com/ final status: 200 (final URL https://www.reverbnation.com/).
- http://reverbnation.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2027-02-11T23:59:59+00:00.
