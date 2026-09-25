# Security Audit Report — docs.microsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://docs.microsoft.com/ |
| Bug bounty program | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| Listed scope domain | docs.microsoft.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 9 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://docs.microsoft.com/ without HttpOnly: bm_mi. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://docs.microsoft.com/ without Secure: ak_bmsc. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://docs.microsoft.com/ without SameSite=Lax/Strict: ak_bmsc, bm_mi. Cross-site request cookies.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for docs.microsoft.com lists 1 name(s) besides the scope host: *.docs.microsoft.com

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://docs.microsoft.com/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://docs.microsoft.com/ -> https://docs.microsoft.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://docs.microsoft.com/ exposes 19 unique Disallow path(s) (/*/answers/*?*filterby=, /*/answers/*?*orderby=, /*/answers/*?*pagesize=, /*/answers/*?*sort=, /*/answers/*?*topics=) and 2 sitemap reference(s)

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on docs.microsoft.com.

### 9. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://docs.microsoft.com/ redirects to https://learn.microsoft.com/en-us/.

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://docs.microsoft.com/ final status: 200 (final URL https://learn.microsoft.com/en-us/).
- http://docs.microsoft.com/ initial status: 301.
- Certificate: Microsoft Corporation Microsoft TLS G2 ECC CA OCSP 06, valid until 2027-04-07T23:37:09+00:00.
