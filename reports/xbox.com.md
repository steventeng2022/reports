# Security Audit Report — xbox.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://xbox.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | xbox.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 3, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 4 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | H2 | Short HSTS max-age | CWE-319 |
| 8 | info | H2c | HSTS not preloaded | CWE-319 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 14 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://xbox.com/ without HttpOnly: x-theme. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://xbox.com/ without SameSite=Lax/Strict: TiPMix, aka_locale, x-ms-routing-name, x-theme, xbcsession. Cross-site request cookies.

### 3. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://xbox.com/; no defense-in-depth against XSS/content injection.

### 4. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond xbox.com: .www.xbox.com, www.xbox.com.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for xbox.com lists 192 name(s) besides the scope host: 425show.dev, aieconomy.microsoft.com, ambetion.be, ambetion.digital, archive.codeplex.com, azurecontainerapp.com, azurecontainerapp.dev, azurecontainerapp.io... (1 no longer resolve)

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `d365iom.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=10886400 (< 1 year): `max-age=10886400; includeSubDomains`.

### 8. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=10886400; includeSubDomains` lacks the preload directive.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://xbox.com/; full URL (incl. query strings) is sent as referrer by default.

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://xbox.com/; browser features (camera, mic, geolocation) unrestricted.

### 11. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://xbox.com/ lists 932 URLs.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://xbox.com/ -> https://www.xbox.com/ (positive check).

### 13. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://xbox.com/ exposes 9 unique Disallow path(s) (/*/contact-us?isChatCallAvailable=false, /*/play/user/*, /*Results?k*, /*Search?q*, /*results?k*) and 1 sitemap reference(s)

### 14. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on xbox.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://xbox.com/ final status: 200 (final URL https://www.xbox.com/zh-TW/).
- http://xbox.com/ initial status: 301.
- Certificate: Microsoft Corporation Microsoft TLS G2 RSA CA OCSP 02, valid until 2026-12-26T10:37:30+00:00.
