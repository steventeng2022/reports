# Security Audit Report — yandex.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yandex.com/ |
| Bug bounty program | [Yandex](https://yandex.com/bugbounty/index) |
| Listed scope domain | yandex.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://yandex.com/ without HttpOnly: _yasc, bh, is_gdpr, is_gdpr_b, yandex_gid, yandexuid, yp, yuidss. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://yandex.com/ without SameSite=Lax/Strict: _yasc, bh, i, is_gdpr, is_gdpr_b, pi, yandex_gid, yandexuid, yashr, yp, yuidss. Cross-site request cookies.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for yandex.com lists 51 name(s) besides the scope host: *.xn--d1acpjx3f.xn--p1ai, *.ya.ru, *.yandex.aero, *.yandex.az, *.yandex.by, *.yandex.co.il, *.yandex.com, *.yandex.com.am...

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://yandex.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://yandex.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://yandex.com/ -> https://yandex.com/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://yandex.com/ exposes 230 unique Disallow path(s) (*maps/covid19*, /403.html, /404.html, /500.html, /?) and 4 sitemap reference(s)

### 9. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://yandex.com (208 bytes); contact: https://ya.cc/t/_rjVQfBG3gkSdX

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://yandex.com/ final status: 200 (final URL https://yandex.com/).
- http://yandex.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign ECC OV SSL CA 2018, valid until 2026-12-29T20:59:59+00:00.
