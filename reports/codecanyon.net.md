# Security Audit Report — codecanyon.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://codecanyon.net/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | codecanyon.net |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://codecanyon.net/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://codecanyon.net/; no defense-in-depth against XSS/content injection.

### 3. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://codecanyon.net/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://codecanyon.net/ -> https://codecanyon.net/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://codecanyon.net/ exposes 30 unique Disallow path(s) (*,*,*, */cart/*, */full_screen_preview/, */item_support/, */screenshots/) and 3 sitemap reference(s)

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://codecanyon.net (277 bytes); contact: https://help.market.envato.com/hc/en-us/requests/new?ticket_form_id=38490

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://codecanyon.net/ final status: 200 (final URL https://codecanyon.net/).
- http://codecanyon.net/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-19T15:44:01+00:00.
