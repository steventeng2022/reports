# Security Audit Report — axios.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://axios.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | axios.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 8 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://axios.com/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://axios.com/. Clients may connect over plain HTTP on first visit.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for axios.com lists 1 name(s) besides the scope host: *.axios.com

### 4. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://axios.com/ lists 1975 URLs.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://axios.com/ -> https://axios.com/ (positive check).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://axios.com/ exposes 7 unique Disallow path(s) (/, /admin/, /api/, /core/*, /login/) and 1 sitemap reference(s)

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on axios.com.

### 8. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://axios.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://axios.com/ final status: 403 (final URL https://www.axios.com/).
- http://axios.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2026-12-10T23:59:59+00:00.
