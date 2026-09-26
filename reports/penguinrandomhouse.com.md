# Security Audit Report — penguinrandomhouse.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://penguinrandomhouse.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | penguinrandomhouse.com |
| Test date | 2026-09-25 19:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 0, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H2c | HSTS not preloaded | CWE-319 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for penguinrandomhouse.com lists 1 name(s) besides the scope host: *.penguinrandomhouse.com

### 2. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubdomains` lacks the preload directive.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://penguinrandomhouse.com/; browser features (camera, mic, geolocation) unrestricted.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://penguinrandomhouse.com/ -> https://www.penguinrandomhouse.com/ (positive check).

## Reproduction notes

- Scanned 2026-09-25 19:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://penguinrandomhouse.com/ final status: 200 (final URL https://www.penguinrandomhouse.com/).
- http://penguinrandomhouse.com/ initial status: 301.
- Certificate: Sectigo Limited Sectigo Public Server Authentication CA DV R36, valid until 2027-01-09T23:59:59+00:00.
