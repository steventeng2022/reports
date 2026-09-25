# Security Audit Report — whatsapp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://whatsapp.com/ |
| Bug bounty program | [Facebook](https://www.facebook.com/whitehat) |
| Listed scope domain | whatsapp.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | X2 | HTTPS homepage returned HTTP 400 | CWE-200 |

## Detailed findings

### 1. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-02T23:59:59+00:00 (7 days left) for whatsapp.com.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for whatsapp.com lists 6 name(s) besides the scope host: *.cdn.whatsapp.net, *.snr.whatsapp.net, *.whatsapp.com, *.whatsapp.net, wa.me, whatsapp.net

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://whatsapp.com/; full URL (incl. query strings) is sent as referrer by default.

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://whatsapp.com/; browser features (camera, mic, geolocation) unrestricted.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://whatsapp.com/ -> https://whatsapp.com/ (positive check).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://whatsapp.com/ exposes 12 unique Disallow path(s) (/, /*.php, /*cursor=, /*fb_comment_id=, /ajax/) and 1 sitemap reference(s)

### 7. [INFO] HTTPS homepage returned HTTP 400 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://whatsapp.com/ responded 400 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://whatsapp.com/ final status: 400 (final URL https://www.whatsapp.com/).
- http://whatsapp.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2026-10-02T23:59:59+00:00.
