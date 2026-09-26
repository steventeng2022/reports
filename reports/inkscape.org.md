# Security Audit Report — inkscape.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://inkscape.org/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | inkscape.org |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 6 | info | H2c | HSTS not preloaded | CWE-319 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 12 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://inkscape.org/; no defense-in-depth against XSS/content injection.

### 2. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://inkscape.org/; browsers may MIME-sniff responses.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://inkscape.org/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for inkscape.org lists 1 name(s) besides the scope host: www.inkscape.org

### 5. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=63072000` does not cover subdomains.

### 6. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=63072000` lacks the preload directive.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://inkscape.org/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://inkscape.org/; browser features (camera, mic, geolocation) unrestricted.

### 9. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://inkscape.org/ returns 403 (no redirect to HTTPS).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://inkscape.org/ exposes 5 unique Disallow path(s) (/, /P3W-451/, /get/, /media/, /static/)

### 11. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on inkscape.org.

### 12. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://inkscape.org/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://inkscape.org/ final status: 403 (final URL https://inkscape.org/).
- http://inkscape.org/ initial status: 403.
- Certificate: Let's Encrypt YE2, valid until 2026-11-20T04:05:44+00:00.
