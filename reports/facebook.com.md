# Security Audit Report — facebook.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://facebook.com/ |
| Bug bounty program | [Facebook](https://www.facebook.com/whitehat) |
| Listed scope domain | facebook.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H2 | Short HSTS max-age | CWE-319 |
| 4 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | X2 | HTTPS homepage returned HTTP 400 | CWE-200 |

## Detailed findings

### 1. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-02T23:59:59+00:00 (7 days left) for facebook.com.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for facebook.com lists 10 name(s) besides the scope host: *.facebook.com, *.facebook.net, *.fbcdn.net, *.fbsbx.com, *.m.facebook.com, *.messenger.com, *.xx.fbcdn.net, *.xy.fbcdn.net...

### 3. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=15552000 (< 1 year): `max-age=15552000; preload`.

### 4. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=15552000; preload` does not cover subdomains.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://facebook.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://facebook.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://facebook.com/ -> https://facebook.com/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://facebook.com/ exposes 44 unique Disallow path(s) (/, /*/plugins/*, /?*next=, /a/bz?, /ajax/)

### 9. [INFO] HTTPS homepage returned HTTP 400 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://facebook.com/ responded 400 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://facebook.com/ final status: 400 (final URL https://www.facebook.com/).
- http://facebook.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2026-10-02T23:59:59+00:00.
