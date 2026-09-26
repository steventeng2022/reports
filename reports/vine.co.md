# Security Audit Report — vine.co

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vine.co/ |
| Bug bounty program | [Twitter](https://hackerone.com/twitter) |
| Listed scope domain | vine.co |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 0, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 3 | info | H2c | HSTS not preloaded | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for vine.co lists 2 name(s) besides the scope host: platform.vine.co, www.vine.co

### 2. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=631138519` does not cover subdomains.

### 3. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=631138519` lacks the preload directive.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://vine.co/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://vine.co/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://vine.co/ -> https://vine.co:443/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://vine.co/ exposes 1 unique Disallow path(s) (User-agent:)

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://vine.co (5081 bytes)

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://vine.co/ final status: 200 (final URL https://vine.co/).
- http://vine.co/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-02-03T23:59:59+00:00.
