# Security Audit Report — googleadservices.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://googleadservices.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | googleadservices.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 9 | info | X2 | HTTPS homepage returned HTTP 404 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://googleadservices.com/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://googleadservices.com/; no defense-in-depth against XSS/content injection.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://googleadservices.com/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for googleadservices.com lists 1 name(s) besides the scope host: *.googleadservices.com

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://googleadservices.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://googleadservices.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://googleadservices.com/ returns 404 (no redirect to HTTPS).

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on googleadservices.com.

### 9. [INFO] HTTPS homepage returned HTTP 404 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://googleadservices.com/ responded 404 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://googleadservices.com/ final status: 404 (final URL https://googleadservices.com/).
- http://googleadservices.com/ initial status: 404.
- Certificate: Google Trust Services WR2, valid until 2026-12-03T19:23:05+00:00.
