# Security Audit Report — mega.nz

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mega.nz/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mega.nz |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://mega.nz/ without HttpOnly: geoip. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://mega.nz/ without SameSite=Lax/Strict: geoip. Cross-site request cookies.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://mega.nz/; browsers may MIME-sniff responses.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for mega.nz lists 1 name(s) besides the scope host: www.mega.nz

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://mega.nz/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://mega.nz/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://mega.nz/ lists 30 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://mega.nz/ -> https://mega.nz (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://mega.nz/ exposes 1 unique Disallow path(s) (/) and 3 sitemap reference(s)

### 10. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://mega.nz (2525 bytes)

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://mega.nz/ final status: 200 (final URL https://mega.nz/).
- http://mega.nz/ initial status: 301.
- Certificate: Let's Encrypt YR2, valid until 2026-11-11T21:02:58+00:00.
