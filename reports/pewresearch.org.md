# Security Audit Report — pewresearch.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pewresearch.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pewresearch.org |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 6, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 7 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 11 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 13 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 14 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://pewresearch.org/ without HttpOnly: _hcc. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://pewresearch.org/ without Secure: _hcc. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://pewresearch.org/ without SameSite=Lax/Strict: _hcc. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://pewresearch.org/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://pewresearch.org/; browsers may MIME-sniff responses.

### 6. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://pewresearch.org/; page may be rendered in a foreign frame.

### 7. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for pewresearch.org lists 1 name(s) besides the scope host: www.pewresearch.org

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://pewresearch.org/; full URL (incl. query strings) is sent as referrer by default.

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://pewresearch.org/; browser features (camera, mic, geolocation) unrestricted.

### 10. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://pewresearch.org/ lists 5 URLs.

### 11. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://pewresearch.org/ -> https://pewresearch.org/ (positive check).

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://pewresearch.org/ exposes 5 unique Disallow path(s) (/?s=, /search, /search/, /wp-admin/, /wp-content/plugins/prc-icon-library/) and 5 sitemap reference(s)

### 13. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on pewresearch.org.

### 14. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://pewresearch.org/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://pewresearch.org/ final status: 403 (final URL https://pewresearch.org/).
- http://pewresearch.org/ initial status: 301.
- Certificate: Let's Encrypt YE1, valid until 2026-12-09T00:07:45+00:00.
