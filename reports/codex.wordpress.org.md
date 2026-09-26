# Security Audit Report — codex.wordpress.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://codex.wordpress.org/ |
| Bug bounty program | [WordPress](https://hackerone.com/wordpress) |
| Listed scope domain | codex.wordpress.org |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 6, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 7 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 8 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 9 | info | H2c | HSTS not preloaded | CWE-319 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt protected | CWE-200 |
| 14 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 15 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://codex.wordpress.org/ without HttpOnly: _hcc. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://codex.wordpress.org/ without Secure: _hcc. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://codex.wordpress.org/ without SameSite=Lax/Strict: _hcc. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://codex.wordpress.org/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://codex.wordpress.org/; browsers may MIME-sniff responses.

### 6. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://codex.wordpress.org/; page may be rendered in a foreign frame.

### 7. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for codex.wordpress.org lists 2 name(s) besides the scope host: *.wordpress.org, wordpress.org

### 8. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 9. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://codex.wordpress.org/; full URL (incl. query strings) is sent as referrer by default.

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://codex.wordpress.org/; browser features (camera, mic, geolocation) unrestricted.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://codex.wordpress.org/ -> https://codex.wordpress.org/ (positive check).

### 13. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 14. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on codex.wordpress.org.

### 15. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://codex.wordpress.org/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://codex.wordpress.org/ final status: 403 (final URL https://codex.wordpress.org/).
- http://codex.wordpress.org/ initial status: 301.
- Certificate: Let's Encrypt YR2, valid until 2026-12-22T19:43:49+00:00.
