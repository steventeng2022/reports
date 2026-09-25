# Security Audit Report — vizio.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vizio.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | vizio.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://vizio.com/; no defense-in-depth against XSS/content injection.

### 2. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://vizio.com/; full URL (incl. query strings) is sent as referrer by default.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://vizio.com/; browser features (camera, mic, geolocation) unrestricted.

### 4. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://vizio.com/ lists 2 URLs.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://vizio.com/ -> https://vizio.com/ (positive check).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://vizio.com/ exposes 2 unique Disallow path(s) (/*?token=*, /setup/verify-email) and 1 sitemap reference(s)

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on vizio.com.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://vizio.com/ final status: 200 (final URL https://www.vizio.com/en/home).
- http://vizio.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-10T23:24:57+00:00.
