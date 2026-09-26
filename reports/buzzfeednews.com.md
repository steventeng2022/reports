# Security Audit Report — buzzfeednews.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://buzzfeednews.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | buzzfeednews.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 0, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for buzzfeednews.com lists 15 name(s) besides the scope host: *.buzzfeed.bio, *.buzzfeed.com, *.buzzfeed.io, *.buzzfeednews.com, *.bzfd.bio, *.contagiousmedia.com, *.stage.buzzfeed.com, *.tasty.co...

### 2. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; preload` does not cover subdomains.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://buzzfeednews.com/; full URL (incl. query strings) is sent as referrer by default.

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://buzzfeednews.com/; browser features (camera, mic, geolocation) unrestricted.

### 5. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://buzzfeednews.com/ lists 4 URLs.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://buzzfeednews.com/ -> https://www.buzzfeednews.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://buzzfeednews.com/ exposes 24 unique Disallow path(s) (*?s=feedpager, *?s=lightbox, *?s=mobile, /, /*.xml$) and 4 sitemap reference(s)

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://buzzfeednews.com (168 bytes); contact: https://www.buzzfeed.com/bug-bounty-program

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://buzzfeednews.com/ final status: 200 (final URL https://www.buzzfeednews.com/).
- http://buzzfeednews.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign Atlas R46 DV TLS CA 2026 Q3, valid until 2027-03-21T12:08:41+00:00.
