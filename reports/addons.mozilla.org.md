# Security Audit Report — addons.mozilla.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://addons.mozilla.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | addons.mozilla.org |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 1, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-26T16:03:05+00:00 (30 days left) for addons.mozilla.org.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for addons.mozilla.org lists 1 name(s) besides the scope host: services.addons.mozilla.org

### 3. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://addons.mozilla.org/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://addons.mozilla.org/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://addons.mozilla.org/ lists 2716 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://addons.mozilla.org/ -> https://addons.mozilla.org/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://addons.mozilla.org/ exposes 260 unique Disallow path(s) (/android/downloads/, /cs/android/collections/, /cs/android/search/, /cs/firefox/collections/, /cs/firefox/collections/4757633/$)

### 10. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on addons.mozilla.org.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://addons.mozilla.org/ final status: 200 (final URL https://addons.mozilla.org/en-US/firefox/).
- http://addons.mozilla.org/ initial status: 301.
- Certificate: Let's Encrypt YR1, valid until 2026-10-26T16:03:05+00:00.
