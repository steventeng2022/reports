# Security Audit Report — msdn.microsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://msdn.microsoft.com/ |
| Bug bounty program | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| Listed scope domain | msdn.microsoft.com |
| Test date | 2026-09-25 02:55 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 9 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://msdn.microsoft.com/ without HttpOnly: bm_mi. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://msdn.microsoft.com/ without Secure: ak_bmsc. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://msdn.microsoft.com/ without SameSite=Lax/Strict: ak_bmsc, bm_mi. Cross-site request cookies.

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://msdn.microsoft.com/; browser features (camera, mic, geolocation) unrestricted.

### 5. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://msdn.microsoft.com/ lists 0 URLs.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://msdn.microsoft.com/ -> https://msdn.microsoft.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://msdn.microsoft.com/ exposes 170 unique Disallow path(s) (/%20library/, /&*, /&loc=, /*%20, /*%20(http) and 3 sitemap reference(s)

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://msdn.microsoft.com (27168 bytes)

### 9. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://msdn.microsoft.com/ redirects to https://learn.microsoft.com/en-us/.

## Reproduction notes

- Scanned 2026-09-25 02:55 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://msdn.microsoft.com/ final status: 200 (final URL https://learn.microsoft.com/en-us/).
- http://msdn.microsoft.com/ initial status: 307.
- Certificate: Microsoft Corporation Microsoft TLS G2 RSA CA OCSP 04, valid until 2027-02-26T02:50:42+00:00.
