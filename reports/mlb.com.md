# Security Audit Report — mlb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mlb.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mlb.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | info | H2 | Short HSTS max-age | CWE-319 |
| 3 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://mlb.com/; no defense-in-depth against XSS/content injection.

### 2. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=604800 (< 1 year): `max-age=604800`.

### 3. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=604800` does not cover subdomains.

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=604800` lacks the preload directive.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://mlb.com/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://mlb.com/ -> https://www.mlb.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://mlb.com/ exposes 76 unique Disallow path(s) (/angels/search, /api/, /app/, /astros/search, /athletics/search) and 5 sitemap reference(s)

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://mlb.com (212 bytes); contact: https://mlb.com/vdp

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://mlb.com/ final status: 200 (final URL https://www.mlb.com/).
- http://mlb.com/ initial status: 301.
- Certificate: Google Trust Services WR3, valid until 2026-12-11T11:05:56+00:00.
