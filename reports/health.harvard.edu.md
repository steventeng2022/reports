# Security Audit Report — health.harvard.edu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://health.harvard.edu/ |
| Bug bounty program | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| Listed scope domain | health.harvard.edu |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://health.harvard.edu/; no defense-in-depth against XSS/content injection.

### 2. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-25T18:38:35+00:00 (30 days left) for health.harvard.edu.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for health.harvard.edu lists 1 name(s) besides the scope host: www.health.harvard.edu

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://health.harvard.edu/; browser features (camera, mic, geolocation) unrestricted.

### 5. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://health.harvard.edu/ lists 5 URLs.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://health.harvard.edu/ -> https://www.health.harvard.edu/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://health.harvard.edu/ exposes 0 unique Disallow path(s)

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on health.harvard.edu.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://health.harvard.edu/ final status: 200 (final URL https://www.health.harvard.edu/).
- http://health.harvard.edu/ initial status: 301.
- Certificate: Let's Encrypt YE2, valid until 2026-10-25T18:38:35+00:00.
