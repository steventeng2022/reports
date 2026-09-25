# Security Audit Report — event.on24.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://event.on24.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | event.on24.com |
| Test date | 2026-09-25 02:55 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | X2 | HTTPS homepage returned HTTP 418 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://event.on24.com/ without HttpOnly: TS14864e2b027. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://event.on24.com/ without SameSite=Lax/Strict: TS14864e2b027. Cross-site request cookies.

### 3. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://event.on24.com/; no defense-in-depth against XSS/content injection.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for event.on24.com lists 2 name(s) besides the scope host: *.on24.com, on24.com

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://event.on24.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://event.on24.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://event.on24.com/ returns 403 (no redirect to HTTPS).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://event.on24.com/ exposes 30 unique Disallow path(s) (/, /clients/, /custom/, /emailBlaster/, /emergency/) and 2 sitemap reference(s)

### 9. [INFO] HTTPS homepage returned HTTP 418 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://event.on24.com/ responded 418 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 02:55 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://event.on24.com/ final status: 418 (final URL https://event.on24.com/).
- http://event.on24.com/ initial status: 403.
- Certificate: Sectigo Limited Sectigo Public Server Authentication CA OV R36, valid until 2027-01-08T23:59:59+00:00.
