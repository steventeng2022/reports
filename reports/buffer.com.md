# Security Audit Report — buffer.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://buffer.com/ |
| Bug bounty program | [Buffer](https://buffer.com/legal#security) |
| Listed scope domain | buffer.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | H2 | Short HSTS max-age | CWE-319 |
| 8 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 9 | info | H2c | HSTS not preloaded | CWE-319 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 13 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 14 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 15 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://buffer.com/ without HttpOnly: AWSALBTG, AWSALBTGCORS. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://buffer.com/ without Secure: AWSALBTG, buffer-marketing. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://buffer.com/ without SameSite=Lax/Strict: AWSALBTG, AWSALBTGCORS, buffer-marketing. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://buffer.com/; no defense-in-depth against XSS/content injection.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for buffer.com lists 1 name(s) besides the scope host: debugger.buffer.com (1 no longer resolve)

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `debugger.buffer.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=15552000 (< 1 year): `max-age=15552000`.

### 8. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=15552000` does not cover subdomains.

### 9. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=15552000` lacks the preload directive.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://buffer.com/; full URL (incl. query strings) is sent as referrer by default.

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://buffer.com/; browser features (camera, mic, geolocation) unrestricted.

### 12. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://buffer.com/ lists 225 URLs.

### 13. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://buffer.com/ -> https://buffer.com:443/ (positive check).

### 14. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://buffer.com/ exposes 8 unique Disallow path(s) (/, /add, /ajax, /button, /docs-custom-code.js) and 8 sitemap reference(s)

### 15. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on buffer.com.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://buffer.com/ final status: 200 (final URL https://buffer.com/).
- http://buffer.com/ initial status: 301.
- Certificate: Let's Encrypt YE2, valid until 2026-11-28T18:46:27+00:00.
