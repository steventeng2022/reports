# Security Audit Report — chronicle.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://chronicle.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | chronicle.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H2 | Short HSTS max-age | CWE-319 |
| 4 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 5 | info | H2c | HSTS not preloaded | CWE-319 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://chronicle.com/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for chronicle.com lists 3 name(s) besides the scope host: *.chronicle.com, *.philanthropy.com, philanthropy.com

### 3. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=15552000 (< 1 year): `max-age=15552000`.

### 4. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=15552000` does not cover subdomains.

### 5. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=15552000` lacks the preload directive.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://chronicle.com/ -> https://www.chronicle.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://chronicle.com/ exposes 1 unique Disallow path(s) (/search)

### 8. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://chronicle.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://chronicle.com/ final status: 403 (final URL https://www.chronicle.com/).
- http://chronicle.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-01-12T23:59:59+00:00.
