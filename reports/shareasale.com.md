# Security Audit Report — shareasale.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://shareasale.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | shareasale.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 3, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H2 | Short HSTS max-age | CWE-319 |
| 6 | info | H2c | HSTS not preloaded | CWE-319 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 10 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 11 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 12 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 13 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://shareasale.com/; no defense-in-depth against XSS/content injection.

### 2. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://shareasale.com/; browsers may MIME-sniff responses.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://shareasale.com/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for shareasale.com lists 1 name(s) besides the scope host: *.shareasale.com

### 5. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=15768000 (< 1 year): `max-age=15768000 ; includeSubDomains`.

### 6. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=15768000 ; includeSubDomains` lacks the preload directive.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://shareasale.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://shareasale.com/; browser features (camera, mic, geolocation) unrestricted.

### 9. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://shareasale.com/ lists 0 URLs.

### 10. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://shareasale.com/ -> https://www.awin.com/us/getting-started-sas?utm_medium=redirect&utm_source=shareasale.com (positive check).

### 11. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://shareasale.com/ exposes 0 unique Disallow path(s)

### 12. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://shareasale.com (147702 bytes)

### 13. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://shareasale.com/ redirects to https://www.awin.com/us/getting-started-sas?utm_medium=redirect&utm_source=shareasale.com.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://shareasale.com/ final status: 200 (final URL https://www.awin.com/us/getting-started-sas?utm_medium=redirect&utm_source=shareasale.com).
- http://shareasale.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2026-11-28T23:59:59+00:00.
