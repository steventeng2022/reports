# Security Audit Report — samsung.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://samsung.com/ |
| Bug bounty program | [Samsung TV](https://samsungtvbounty.com) |
| Listed scope domain | samsung.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 8, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 6 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 7 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 8 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 9 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt protected | CWE-200 |
| 14 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 15 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://samsung.com/ without HttpOnly: country_codes, country_region, device_type. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://samsung.com/ without Secure: country_codes, country_region, device_type. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://samsung.com/ without SameSite=Lax/Strict: AKA_A2, country_codes, country_region, device_type, s_fpid. Cross-site request cookies.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://samsung.com/. Clients may connect over plain HTTP on first visit.

### 5. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://samsung.com/; no defense-in-depth against XSS/content injection.

### 6. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://samsung.com/; browsers may MIME-sniff responses.

### 7. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://samsung.com/; page may be rendered in a foreign frame.

### 8. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-23T23:59:59+00:00 (28 days left) for samsung.com.

### 9. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for samsung.com lists 1 name(s) besides the scope host: *.samsung.com

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://samsung.com/; full URL (incl. query strings) is sent as referrer by default.

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://samsung.com/; browser features (camera, mic, geolocation) unrestricted.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://samsung.com/ -> https://www.samsung.com/ (positive check).

### 13. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 14. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on samsung.com.

### 15. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://samsung.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://samsung.com/ final status: 403 (final URL https://www.samsung.com/).
- http://samsung.com/ initial status: 301.
- Certificate: Sectigo Limited Sectigo Public Server Authentication CA OV R36, valid until 2026-10-23T23:59:59+00:00.
