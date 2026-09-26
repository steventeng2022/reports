# Security Audit Report — medium.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://medium.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | medium.com |
| Test date | 2026-09-25 19:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 0, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 3 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 4 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 5 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for medium.com lists 1 name(s) besides the scope host: *.medium.com

### 2. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://medium.com/ -> https://medium.com/ (positive check).

### 3. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://medium.com/ exposes 16 unique Disallow path(s) (/, /*/*/edit$, /*/*source=, /*/edit$, /*/search/*?q=) and 1 sitemap reference(s)

### 4. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on medium.com.

### 5. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://medium.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 19:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://medium.com/ final status: 403 (final URL https://medium.com/).
- http://medium.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-04T21:48:00+00:00.
