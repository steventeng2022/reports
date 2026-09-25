# Security Audit Report — cdn.shopify.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cdn.shopify.com/ |
| Bug bounty program | [Shopify](https://hackerone.com/shopify) |
| Listed scope domain | cdn.shopify.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | info | H2 | Short HSTS max-age | CWE-319 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 5 | info | R1 | robots.txt protected | CWE-200 |
| 6 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 7 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://cdn.shopify.com/; no defense-in-depth against XSS/content injection.

### 2. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=15552000 (< 1 year): `max-age=15552000; includeSubDomains; preload`.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://cdn.shopify.com/; browser features (camera, mic, geolocation) unrestricted.

### 4. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://cdn.shopify.com/ returns 403 (no redirect to HTTPS).

### 5. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 6. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on cdn.shopify.com.

### 7. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://cdn.shopify.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://cdn.shopify.com/ final status: 403 (final URL https://cdn.shopify.com/).
- http://cdn.shopify.com/ initial status: 403.
- Certificate: Google Trust Services WE1, valid until 2026-11-06T01:46:39+00:00.
