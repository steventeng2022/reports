# Security Audit Report — store.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://store.google.com/ |
| Bug bounty program | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| Listed scope domain | store.google.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://store.google.com/ without SameSite=Lax/Strict: NID. Cross-site request cookies.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for store.google.com lists 65 name(s) besides the scope host: *.aistudio.google.com, *.android.com, *.appengine.google.com, *.bdn.dev, *.cloud.google.com, *.crowdsource.google.com, *.datacompute.google.com, *.flash.android.com...

### 3. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://store.google.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://store.google.com/ lists 36 URLs.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://store.google.com/ -> https://store.google.com/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://store.google.com/ exposes 38 unique Disallow path(s) (/*/accessoriesdata, /*/addtocart, /*/archive, /*/cancel, /*/cart) and 1 sitemap reference(s)

### 9. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on store.google.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://store.google.com/ final status: 200 (final URL https://store.google.com/?hl=zh-TW).
- http://store.google.com/ initial status: 301.
- Certificate: Google Trust Services WE2, valid until 2026-12-03T19:22:00+00:00.
