# Security Audit Report — en.wikipedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://en.wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | en.wikipedia.org |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://en.wikipedia.org/ without SameSite=Lax/Strict: WMF-DP, WMF-Uniq. Cross-site request cookies.

### 2. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://en.wikipedia.org/; page may be rendered in a foreign frame.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for en.wikipedia.org lists 41 name(s) besides the scope host: *.m.mediawiki.org, *.m.wikibooks.org, *.m.wikidata.org, *.m.wikimedia.org, *.m.wikinews.org, *.m.wikipedia.org, *.m.wikiquote.org, *.m.wikisource.org...

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://en.wikipedia.org/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://en.wikipedia.org/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://en.wikipedia.org/ -> https://en.wikipedia.org/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://en.wikipedia.org/ exposes 410 unique Disallow path(s) (#, /, /api/, /trap/, /w/) and 1 sitemap reference(s)

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://en.wikipedia.org (222 bytes); contact: mailto:security@wikimedia.org

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://en.wikipedia.org/ final status: 200 (final URL https://en.wikipedia.org/wiki/Main_Page).
- http://en.wikipedia.org/ initial status: 301.
- Certificate: Let's Encrypt YE2, valid until 2026-11-03T19:15:40+00:00.
