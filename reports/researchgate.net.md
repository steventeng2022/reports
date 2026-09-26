# Security Audit Report — researchgate.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://researchgate.net/ |
| Bug bounty program | [Research Gate](https://explore.researchgate.net/display/support/Security+and+vulnerability) |
| Listed scope domain | researchgate.net |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 2, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 7 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://researchgate.net/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://researchgate.net/; no defense-in-depth against XSS/content injection.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for researchgate.net lists 1 name(s) besides the scope host: *.researchgate.net

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://researchgate.net/ -> https://researchgate.net/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://researchgate.net/ exposes 7 unique Disallow path(s) (/cdn-cgi/, /connector/, /firststeps., /lite.publication.PublicationRequestFulltextPromo.requestFulltext.html, /plugins.)

### 6. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on researchgate.net.

### 7. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://researchgate.net/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://researchgate.net/ final status: 403 (final URL https://www.researchgate.net/).
- http://researchgate.net/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-14T13:54:34+00:00.
