# Security Audit Report — api.whatsapp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://api.whatsapp.com/ |
| Bug bounty program | [Facebook](https://www.facebook.com/whitehat) |
| Listed scope domain | api.whatsapp.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 8 | info | X2 | HTTPS homepage returned HTTP 400 | CWE-200 |

## Detailed findings

### 1. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-02T23:59:59+00:00 (7 days left) for api.whatsapp.com.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for api.whatsapp.com lists 7 name(s) besides the scope host: *.cdn.whatsapp.net, *.snr.whatsapp.net, *.whatsapp.com, *.whatsapp.net, wa.me, whatsapp.com, whatsapp.net

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://api.whatsapp.com/; full URL (incl. query strings) is sent as referrer by default.

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://api.whatsapp.com/; browser features (camera, mic, geolocation) unrestricted.

### 5. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://api.whatsapp.com/ returns 403 (no redirect to HTTPS).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://api.whatsapp.com/ exposes 1 unique Disallow path(s) (/)

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on api.whatsapp.com.

### 8. [INFO] HTTPS homepage returned HTTP 400 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://api.whatsapp.com/ responded 400 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://api.whatsapp.com/ final status: 400 (final URL https://api.whatsapp.com/).
- http://api.whatsapp.com/ initial status: 403.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2026-10-02T23:59:59+00:00.
