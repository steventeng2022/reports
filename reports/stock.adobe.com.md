# Security Audit Report — stock.adobe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stock.adobe.com/ |
| Bug bounty program | [Adobe](https://hackerone.com/adobe) |
| Listed scope domain | stock.adobe.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 3, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H2c | HSTS not preloaded | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 11 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://stock.adobe.com/ without HttpOnly: datadome. Readable by client-side script.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://stock.adobe.com/; no defense-in-depth against XSS/content injection.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://stock.adobe.com/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for stock.adobe.com lists 1 name(s) besides the scope host: *.stock.adobe.com

### 5. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://stock.adobe.com/; full URL (incl. query strings) is sent as referrer by default.

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://stock.adobe.com/; browser features (camera, mic, geolocation) unrestricted.

### 8. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://stock.adobe.com/ returns 403 (no redirect to HTTPS).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://stock.adobe.com/ exposes 68 unique Disallow path(s) (*/%3Cloc%3E/, */Ajax/, */Ajax/MediaData/, */Ajax/Similar/, */Download/) and 2 sitemap reference(s)

### 10. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on stock.adobe.com.

### 11. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://stock.adobe.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://stock.adobe.com/ final status: 403 (final URL https://stock.adobe.com/).
- http://stock.adobe.com/ initial status: 403.
- Certificate: Let's Encrypt YR1, valid until 2026-11-28T15:38:51+00:00.
