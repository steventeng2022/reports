# Security Audit Report — plaza.rakuten.co.jp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://plaza.rakuten.co.jp/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | plaza.rakuten.co.jp |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://plaza.rakuten.co.jp/ without SameSite=Lax/Strict: cuid, hamo. Cross-site request cookies.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://plaza.rakuten.co.jp/. Clients may connect over plain HTTP on first visit.

### 3. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://plaza.rakuten.co.jp/; no defense-in-depth against XSS/content injection.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for plaza.rakuten.co.jp lists 2 name(s) besides the scope host: *.rakuten.co.jp, rakuten.co.jp

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://plaza.rakuten.co.jp/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://plaza.rakuten.co.jp/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://plaza.rakuten.co.jp/ -> https://plaza.rakuten.co.jp/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://plaza.rakuten.co.jp/ exposes 1 unique Disallow path(s) (/*comment)

### 9. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on plaza.rakuten.co.jp.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://plaza.rakuten.co.jp/ final status: 200 (final URL https://plaza.rakuten.co.jp/).
- http://plaza.rakuten.co.jp/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2027-04-04T23:59:59+00:00.
