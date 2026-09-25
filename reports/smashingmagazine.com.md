# Security Audit Report — smashingmagazine.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://smashingmagazine.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | smashingmagazine.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://smashingmagazine.com/; no defense-in-depth against XSS/content injection.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for smashingmagazine.com lists 1 name(s) besides the scope host: *.smashingmagazine.com

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://smashingmagazine.com/; browser features (camera, mic, geolocation) unrestricted.

### 4. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://smashingmagazine.com/ lists 2248 URLs.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://smashingmagazine.com/ -> https://smashingmagazine.com/ (positive check).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://smashingmagazine.com/ exposes 188 unique Disallow path(s) (//provide.smashingmagazine.com/create-demo-extension-examples/demo1/, //provide.smashingmagazine.com/create-demo-extension-examples/demo2/, //provide.smashingmagazine.com/create-demo-extension-examples/demo3/, //provide.smashingmagazine.com/create-demo-extension-examples/smashing/, //provide.smashingmagazine.com/eBooks/*) and 1 sitemap reference(s)

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on smashingmagazine.com.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://smashingmagazine.com/ final status: 200 (final URL https://www.smashingmagazine.com/).
- http://smashingmagazine.com/ initial status: 301.
- Certificate: Let's Encrypt YE2, valid until 2026-11-24T08:06:49+00:00.
