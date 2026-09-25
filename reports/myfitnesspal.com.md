# Security Audit Report — myfitnesspal.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://myfitnesspal.com/ |
| Bug bounty program | [UNDER ARMOUR](https://bugcrowd.com/underarmour) |
| Listed scope domain | myfitnesspal.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 2, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://myfitnesspal.com/ without HttpOnly: anon-device-id. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://myfitnesspal.com/ without SameSite=Lax/Strict: anon-device-id. Cross-site request cookies.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for myfitnesspal.com lists 4 name(s) besides the scope host: *.dev.myfitnesspal.com, *.labs.myfitnesspal.com, *.myfitnesspal.com, dev.myfitnesspal.com (1 no longer resolve)

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `dev.myfitnesspal.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://myfitnesspal.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://myfitnesspal.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://myfitnesspal.com/ lists 8 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://myfitnesspal.com/ -> https://myfitnesspal.com/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://myfitnesspal.com/ exposes 47 unique Disallow path(s) (/, /*/404, /*/500, /404, /500) and 1 sitemap reference(s)

### 10. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://myfitnesspal.com (347 bytes); contact: https://bugcrowd.com/engagements/myfitnesspal-mbb

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://myfitnesspal.com/ final status: 200 (final URL https://www.myfitnesspal.com/).
- http://myfitnesspal.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-16T21:05:44+00:00.
