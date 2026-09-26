# Security Audit Report — disqus.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://disqus.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | disqus.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 3 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H2 | Short HSTS max-age | CWE-319 |
| 6 | info | H2c | HSTS not preloaded | CWE-319 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 10 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 11 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 12 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://disqus.com/; no defense-in-depth against XSS/content injection.

### 2. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://disqus.com/; page may be rendered in a foreign frame.

### 3. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-16T23:59:59+00:00 (20 days left) for disqus.com.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for disqus.com lists 1 name(s) besides the scope host: *.disqus.com

### 5. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=300 (< 1 year): `max-age=300; includeSubdomains`.

### 6. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=300; includeSubdomains` lacks the preload directive.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://disqus.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://disqus.com/; browser features (camera, mic, geolocation) unrestricted.

### 9. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://disqus.com/ lists 11 URLs.

### 10. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://disqus.com/ -> https://disqus.com/ (positive check).

### 11. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://disqus.com/ exposes 2 unique Disallow path(s) (/forgot, /reset)

### 12. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on disqus.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://disqus.com/ final status: 200 (final URL https://disqus.com/).
- http://disqus.com/ initial status: 301.
- Certificate: Sectigo Limited Sectigo Public Server Authentication CA DV R36, valid until 2026-10-16T23:59:59+00:00.

## Active agent cross-check (wave 7-9 aggressive scan on main - disqus.com)

Total findings: **9** - latest aggressive-method scan (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | info | T2 | TLS certificate expiring within 22 days | CWE-295 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | I26 | humans.txt exposed (team/contact enumeration) | CWE-200 |
