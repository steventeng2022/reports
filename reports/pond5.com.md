# Security Audit Report — pond5.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pond5.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pond5.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 4 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt protected | CWE-200 |
| 11 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 12 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://pond5.com/ without HttpOnly: datadome. Readable by client-side script.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://pond5.com/; no defense-in-depth against XSS/content injection.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://pond5.com/; browsers may MIME-sniff responses.

### 4. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://pond5.com/; page may be rendered in a foreign frame.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for pond5.com lists 1 name(s) besides the scope host: *.pond5.com

### 6. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; preload` does not cover subdomains.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://pond5.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://pond5.com/; browser features (camera, mic, geolocation) unrestricted.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://pond5.com/ -> https://pond5.com/ (positive check).

### 10. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 11. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on pond5.com.

### 12. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://pond5.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://pond5.com/ final status: 403 (final URL https://pond5.com/).
- http://pond5.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2026-11-23T23:59:59+00:00.

## Active agent cross-check (wave 7-9 aggressive scan on main - pond5.com)

Total findings: **7** - latest aggressive-method scan (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
