# Security Audit Report — is.gd

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://is.gd/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | is.gd |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 2, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 7 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://is.gd/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://is.gd/. Clients may connect over plain HTTP on first visit.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for is.gd lists 1 name(s) besides the scope host: *.is.gd

### 4. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://is.gd/ lists 0 URLs.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://is.gd/ -> https://is.gd/ (positive check).

### 6. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://is.gd (2225 bytes)

### 7. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://is.gd/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://is.gd/ final status: 403 (final URL https://is.gd/).
- http://is.gd/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-11T11:43:04+00:00.
