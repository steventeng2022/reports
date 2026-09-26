# Security Audit Report — pitchfork.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pitchfork.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | pitchfork.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://pitchfork.com/ without HttpOnly: CN_geo_country_code, CN_segments, CN_xid, xid1. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://pitchfork.com/ without SameSite=Lax/Strict: CN_geo_country_code, CN_segments, CN_xid, CN_xid_refresh, xid1. Cross-site request cookies.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://pitchfork.com/. Clients may connect over plain HTTP on first visit.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for pitchfork.com lists 1 name(s) besides the scope host: *.pitchfork.com

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://pitchfork.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://pitchfork.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://pitchfork.com/ lists 60 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://pitchfork.com/ -> https://pitchfork.com/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://pitchfork.com/ exposes 13 unique Disallow path(s) (/, /*?, /account/, /auth/, /cdn-cgi/) and 8 sitemap reference(s)

### 10. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on pitchfork.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://pitchfork.com/ final status: 200 (final URL https://pitchfork.com/).
- http://pitchfork.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2027-03-09T23:59:59+00:00.
