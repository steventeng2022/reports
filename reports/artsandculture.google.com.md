# Security Audit Report — artsandculture.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://artsandculture.google.com/ |
| Bug bounty program | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| Listed scope domain | artsandculture.google.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://artsandculture.google.com/ without SameSite=Lax/Strict: NID. Cross-site request cookies.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://artsandculture.google.com/. Clients may connect over plain HTTP on first visit.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for artsandculture.google.com lists 1 name(s) besides the scope host: *.artsandculture.google.com

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://artsandculture.google.com/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://artsandculture.google.com/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://artsandculture.google.com/ -> https://artsandculture.google.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://artsandculture.google.com/ exposes 2 unique Disallow path(s) (/api/*, /incognito/*) and 1 sitemap reference(s)

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on artsandculture.google.com.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://artsandculture.google.com/ final status: 200 (final URL https://artsandculture.google.com/).
- http://artsandculture.google.com/ initial status: 301.
- Certificate: Google Trust Services WE2, valid until 2026-12-03T19:22:31+00:00.
