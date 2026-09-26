# Security Audit Report — waze.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://waze.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | waze.com |
| Test date | 2026-09-26 01:40 UTC |
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
| 6 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for waze.com lists 5 name(s) besides the scope host: *.waze.co.il, *.waze.com, *.world.waze.com, waze.co.il, world.waze.com

### 2. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://waze.com/; browser features (camera, mic, geolocation) unrestricted.

### 3. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://waze.com/ lists 5 URLs.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://waze.com/ -> https://waze.com/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://waze.com/ exposes 25 unique Disallow path(s) (/Descartes, /RoutingManager, /_user/api, /discuss/, /discuss/*?*api_key*) and 1 sitemap reference(s)

### 6. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://waze.com (275 bytes); contact: https://g.co/vulnz

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://waze.com/ final status: 200 (final URL https://www.waze.com/).
- http://waze.com/ initial status: 301.
- Certificate: Google Trust Services WR3, valid until 2026-11-28T20:51:55+00:00.
