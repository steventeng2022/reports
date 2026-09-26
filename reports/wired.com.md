# Security Audit Report — wired.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wired.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | wired.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 10 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 11 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 12 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://wired.com/ without HttpOnly: CN_geo_country_code, CN_segments, CN_xid, xid1. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://wired.com/ without SameSite=Lax/Strict: CN_geo_country_code, CN_segments, CN_xid, CN_xid_refresh, xid1. Cross-site request cookies.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://wired.com/. Clients may connect over plain HTTP on first visit.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for wired.com lists 91 name(s) besides the scope host: *.worldofinteriors.com, *.worldofinteriors.uk, admexico.com.mx, admiddleeast.com, allure.com, architecturaldigest.com, architecturaldigest.com.mx, arstechnica.co.uk... (2 no longer resolve)

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `condenastdigital.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `condenastdigital.de` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://wired.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://wired.com/; browser features (camera, mic, geolocation) unrestricted.

### 9. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://wired.com/ lists 60 URLs.

### 10. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://wired.com/ -> https://www.wired.com/ (positive check).

### 11. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://wired.com/ exposes 14 unique Disallow path(s) (*/testing-products-, /, /*?, /account/, /auth/) and 7 sitemap reference(s)

### 12. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on wired.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://wired.com/ final status: 200 (final URL https://www.wired.com/).
- http://wired.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2026-11-21T23:59:59+00:00.
