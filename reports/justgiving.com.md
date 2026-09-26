# Security Audit Report — justgiving.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://justgiving.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | justgiving.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 1, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://justgiving.com/; no defense-in-depth against XSS/content injection.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for justgiving.com lists 1 name(s) besides the scope host: *.justgiving.com

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://justgiving.com/; browser features (camera, mic, geolocation) unrestricted.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://justgiving.com/ -> https://justgiving.com/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://justgiving.com/ exposes 6 unique Disallow path(s) (/, /charities/beta/account/login, /charity/search, /fundraiser/search, /share-success/) and 1 sitemap reference(s)

### 6. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://justgiving.com (236 bytes); contact: mailto:security@blackbaud.com

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://justgiving.com/ final status: 200 (final URL https://justgiving.com/).
- http://justgiving.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2026-12-01T23:59:59+00:00.
