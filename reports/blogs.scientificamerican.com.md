# Security Audit Report — blogs.scientificamerican.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blogs.scientificamerican.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | blogs.scientificamerican.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H2c | HSTS not preloaded | CWE-319 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 6 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond blogs.scientificamerican.com: www.scientificamerican.com.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for blogs.scientificamerican.com lists 4 name(s) besides the scope host: *.sciam.com, *.scientificamerican.com, sciam.com, scientificamerican.com

### 3. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://blogs.scientificamerican.com/ -> https://blogs.scientificamerican.com/ (positive check).

### 5. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on blogs.scientificamerican.com.

### 6. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://blogs.scientificamerican.com/ redirects to https://www.scientificamerican.com/.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://blogs.scientificamerican.com/ final status: 200 (final URL https://www.scientificamerican.com/).
- http://blogs.scientificamerican.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2026-12-09T23:59:59+00:00.
