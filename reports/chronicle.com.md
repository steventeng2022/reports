# Security Audit Report — chronicle.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://chronicle.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | chronicle.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 1, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H2 | Short HSTS max-age | CWE-319 |
| 5 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 6 | info | H2c | HSTS not preloaded | CWE-319 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://chronicle.com/ without SameSite=Lax/Strict: __cf_bm, _cfuvid. Cross-site request cookies.

### 2. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond chronicle.com: chronicle.com, CHRON.NOSLUUUID=98e6ae13-1ce2-45a7-8b35-f3cc24af518b.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for chronicle.com lists 3 name(s) besides the scope host: *.chronicle.com, *.philanthropy.com, philanthropy.com

### 4. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=15552000 (< 1 year): `max-age=15552000`.

### 5. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=15552000` does not cover subdomains.

### 6. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=15552000` lacks the preload directive.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://chronicle.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://chronicle.com/; browser features (camera, mic, geolocation) unrestricted.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://chronicle.com/ -> https://www.chronicle.com/ (positive check).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://chronicle.com/ exposes 1 unique Disallow path(s) (/search)

### 11. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on chronicle.com.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://chronicle.com/ final status: 200 (final URL https://www.chronicle.com/).
- http://chronicle.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-01-12T23:59:59+00:00.
