# Security Audit Report — aub.edu.lb

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aub.edu.lb/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | aub.edu.lb |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://aub.edu.lb/. Clients may connect over plain HTTP on first visit.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for aub.edu.lb lists 6 name(s) besides the scope host: *.aub.edu, *.aub.edu.lb, *.aubmc.org, *.aubmc.org.lb, aubmc.org, aubmc.org.lb

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://aub.edu.lb/; full URL (incl. query strings) is sent as referrer by default.

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://aub.edu.lb/; browser features (camera, mic, geolocation) unrestricted.

### 5. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://aub.edu.lb/ lists 14 URLs.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://aub.edu.lb/ -> https://aub.edu.lb/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://aub.edu.lb/ exposes 5 unique Disallow path(s) (/*?*/, /_catalogs/, /_layouts/, /register/, /search/) and 1 sitemap reference(s)

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://aub.edu.lb/ final status: 200 (final URL https://aub.edu.lb/).
- http://aub.edu.lb/ initial status: 307.
- Certificate: Hellenic Academic and Research Institutions CA GEANT TLS RSA 1, valid until 2027-02-06T23:39:42+00:00.
