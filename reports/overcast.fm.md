# Security Audit Report — overcast.fm

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://overcast.fm/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | overcast.fm |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 0, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for overcast.fm lists 1 name(s) besides the scope host: *.overcast.fm

### 2. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://overcast.fm/; browser features (camera, mic, geolocation) unrestricted.

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://overcast.fm/ -> https://overcast.fm/ (positive check).

### 4. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on overcast.fm.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://overcast.fm/ final status: 200 (final URL https://overcast.fm/).
- http://overcast.fm/ initial status: 302.
- Certificate: Let's Encrypt YR2, valid until 2026-12-20T23:05:00+00:00.
