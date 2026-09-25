# Security Audit Report — 1drv.ms

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://1drv.ms/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | 1drv.ms |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 3, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | H2c | HSTS not preloaded | CWE-319 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 13 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 14 | info | X2 | HTTPS homepage returned HTTP 404 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://1drv.ms/; no defense-in-depth against XSS/content injection.

### 2. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://1drv.ms/; browsers may MIME-sniff responses.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://1drv.ms/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for 1drv.ms lists 138 name(s) besides the scope host: *.1drv.com, *.ADMINSVC.I001.1drv.com, *.ADMINSVC.P001.1drv.com, *.API.P001.1drv.com, *.CAMP.I001.1drv.com, *.CONFIG.I001.1drv.com, *.DEPLOYMGR.P001.1drv.com, *.JOB.P001.1drv.com... (6 no longer resolve)

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `device.ra.live.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `df.policies.live.net` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `df.s2s-policies.live.net` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 8. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://1drv.ms/; full URL (incl. query strings) is sent as referrer by default.

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://1drv.ms/; browser features (camera, mic, geolocation) unrestricted.

### 11. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://1drv.ms/ returns 404 (no redirect to HTTPS).

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://1drv.ms/ exposes 1 unique Disallow path(s) (/)

### 13. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on 1drv.ms.

### 14. [INFO] HTTPS homepage returned HTTP 404 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://1drv.ms/ responded 404 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://1drv.ms/ final status: 404 (final URL https://1drv.ms/).
- http://1drv.ms/ initial status: 404.
- Certificate: Microsoft Corporation Microsoft TLS G2 RSA CA OCSP 04, valid until 2027-03-19T06:06:01+00:00.
