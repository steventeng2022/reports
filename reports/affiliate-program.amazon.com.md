# Security Audit Report — affiliate-program.amazon.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://affiliate-program.amazon.com/ |
| Bug bounty program | [Amazon](https://hackerone.com/amazonvrp) |
| Listed scope domain | affiliate-program.amazon.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 4, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://affiliate-program.amazon.com/ without HttpOnly: i18n-prefs, lc-main, session-id, session-id-time. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://affiliate-program.amazon.com/ without Secure: i18n-prefs, lc-main. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://affiliate-program.amazon.com/ without SameSite=Lax/Strict: i18n-prefs, lc-main, session-id, session-id-time, sp-cdn. Cross-site request cookies.

### 4. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://affiliate-program.amazon.com/; page may be rendered in a foreign frame.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for affiliate-program.amazon.com lists 1 name(s) besides the scope host: associates.amazon.com

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://affiliate-program.amazon.com/; full URL (incl. query strings) is sent as referrer by default.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://affiliate-program.amazon.com/ -> https://affiliate-program.amazon.com/ (positive check).

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on affiliate-program.amazon.com.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://affiliate-program.amazon.com/ final status: 200 (final URL https://affiliate-program.amazon.com/).
- http://affiliate-program.amazon.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2026-12-28T23:59:59+00:00.
