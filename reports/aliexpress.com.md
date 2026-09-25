# Security Audit Report — aliexpress.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aliexpress.com/ |
| Bug bounty program | [Alibaba](https://hackerone.com/alibaba) |
| Listed scope domain | aliexpress.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 7, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 6 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 7 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 8 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 14 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://aliexpress.com/ without HttpOnly: acs_usuc_t, aep_usuc_f, intl_locale, xman_us_f. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://aliexpress.com/ without Secure: intl_common_forever, intl_locale. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://aliexpress.com/ without SameSite=Lax/Strict: acs_usuc_t, aep_usuc_f, intl_common_forever, intl_locale, xman_f, xman_t, xman_us_f. Cross-site request cookies.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://aliexpress.com/. Clients may connect over plain HTTP on first visit.

### 5. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://aliexpress.com/; no defense-in-depth against XSS/content injection.

### 6. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://aliexpress.com/; browsers may MIME-sniff responses.

### 7. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://aliexpress.com/; page may be rendered in a foreign frame.

### 8. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for aliexpress.com lists 91 name(s) besides the scope host: *.acs.aliexpress.com, *.acs.aliexpress.ru, *.ae.alibaba.com, *.ae.aliexpress.com, *.aecategoryadmin.aliexpress.com, *.aliexpress-media.com, *.aliexpress-tech-open.com, *.aliexpress.com...

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://aliexpress.com/; full URL (incl. query strings) is sent as referrer by default.

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://aliexpress.com/; browser features (camera, mic, geolocation) unrestricted.

### 11. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://aliexpress.com/ lists 0 URLs.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://aliexpress.com/ -> https://aliexpress.com/ (positive check).

### 13. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://aliexpress.com/ exposes 36 unique Disallow path(s) (*/aeglodetailweb/api/msite/item?productId*, /*Ajax.htm$, /*ajax.htm$, /*mmend.htm$, /*store/group/*) and 8 sitemap reference(s)

### 14. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://aliexpress.com (13830 bytes)

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://aliexpress.com/ final status: 200 (final URL https://www.aliexpress.com/).
- http://aliexpress.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign GCC R3 OV TLS CA 2024, valid until 2026-12-03T11:16:15+00:00.
