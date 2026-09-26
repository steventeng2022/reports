# Security Audit Report — m.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://m.me/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | m.me |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 7 | info | X2 | HTTPS homepage returned HTTP 400 | CWE-200 |

## Detailed findings

### 1. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-03T23:59:59+00:00 (7 days left) for m.me.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for m.me lists 1 name(s) besides the scope host: *.m.me

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://m.me/; full URL (incl. query strings) is sent as referrer by default.

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://m.me/; browser features (camera, mic, geolocation) unrestricted.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://m.me/ -> https://m.me/ (positive check).

### 6. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on m.me.

### 7. [INFO] HTTPS homepage returned HTTP 400 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://m.me/ responded 400 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://m.me/ final status: 400 (final URL https://m.me/).
- http://m.me/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2026-10-03T23:59:59+00:00.
