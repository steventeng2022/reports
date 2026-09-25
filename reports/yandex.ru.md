# Security Audit Report — yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yandex.ru/ |
| Bug bounty program | [Yandex](https://yandex.com/bugbounty/index) |
| Listed scope domain | yandex.ru |
| Test date | 2026-09-25 13:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H2c | HSTS not preloaded | CWE-319 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://yandex.ru/ without HttpOnly: mda2_beacon, mda2_domains, ys. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://yandex.ru/ without SameSite=Lax/Strict: mda2_beacon, mda2_domains, ys. Cross-site request cookies.

### 3. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond yandex.ru: .passport.yandex.ru.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for yandex.ru lists 51 name(s) besides the scope host: *.xn--d1acpjx3f.xn--p1ai, *.ya.ru, *.yandex.aero, *.yandex.az, *.yandex.by, *.yandex.co.il, *.yandex.com, *.yandex.com.am...

### 5. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=315360000; includeSubDomains` lacks the preload directive.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://yandex.ru/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://yandex.ru/ -> https://yandex.ru/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://yandex.ru/ exposes 249 unique Disallow path(s) (*maps/covid19*, /403.html, /404.html, /500.html, /8bit-fest/parents) and 19 sitemap reference(s)

### 9. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://yandex.ru (208 bytes); contact: https://ya.cc/t/_rjVQfBG3gkSdX

## Reproduction notes

- Scanned 2026-09-25 13:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://yandex.ru/ final status: 200 (final URL https://sso.passport.yandex.ru/push?uuid=474173cc-6a36-49ae-ac58-04c0a7ff66bb&retpath=https%3A%2F%2Fdzen.ru%2F%3Fyredirect%3Dtrue%26is_autologin_ya%3Dtrue).
- http://yandex.ru/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign ECC OV SSL CA 2018, valid until 2026-12-29T20:59:59+00:00.
