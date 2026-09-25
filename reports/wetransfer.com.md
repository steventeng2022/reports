# Security Audit Report — wetransfer.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wetransfer.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | wetransfer.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 3 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for wetransfer.com lists 1 name(s) besides the scope host: *.wetransfer.com

### 2. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://wetransfer.com/; browser features (camera, mic, geolocation) unrestricted.

### 3. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://wetransfer.com/ lists 5 URLs.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://wetransfer.com/ -> https://wetransfer.com/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://wetransfer.com/ exposes 24 unique Disallow path(s) (/*?*, /account-verification, /account/, /api/, /checkout) and 1 sitemap reference(s)

### 6. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on wetransfer.com.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://wetransfer.com/ final status: 200 (final URL https://wetransfer.com/).
- http://wetransfer.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2027-02-06T23:59:59+00:00.
