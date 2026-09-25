# Security Audit Report — zen.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zen.yandex.ru/ |
| Bug bounty program | [Yandex](https://yandex.com/bugbounty/index) |
| Listed scope domain | zen.yandex.ru |
| Test date | 2026-09-25 06:31 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 2, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | H2c | HSTS not preloaded | CWE-319 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 12 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://zen.yandex.ru/ without HttpOnly: mda2_beacon, mda2_domains, ys. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://zen.yandex.ru/ without SameSite=Lax/Strict: mda2_beacon, mda2_domains, ys. Cross-site request cookies.

### 3. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond zen.yandex.ru: .passport.yandex.ru.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for zen.yandex.ru lists 46 name(s) besides the scope host: *.zen.yandex.com, *.zen.yandex.ru, dzen.ya.ru, dzen.yandex.ru, main.zdevx.yandex.ru, www.zen.yandex.az, www.zen.yandex.by, www.zen.yandex.co.il... (1 no longer resolve)

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `main.zdevx.yandex.ru` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=315360000; includeSubDomains` lacks the preload directive.

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://zen.yandex.ru/; browser features (camera, mic, geolocation) unrestricted.

### 8. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://zen.yandex.ru/ lists 0 URLs.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://zen.yandex.ru/ -> https://dzen.ru/ (positive check).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://zen.yandex.ru/ exposes 51 unique Disallow path(s) (/*/url, /*?etext=, /*?sso_failed=, /*?utm*, /*_csrf) and 28 sitemap reference(s)

### 11. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://zen.yandex.ru (3075 bytes)

### 12. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://zen.yandex.ru/ redirects to https://sso.passport.yandex.ru/push?uuid=ead76e2c-4e12-4d08-bd3d-52d358275133&retpath=https%3A%2F%2Fdzen.ru%2F%3Fis_autologin_ya%3Dtrue.

## Reproduction notes

- Scanned 2026-09-25 06:31 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://zen.yandex.ru/ final status: 200 (final URL https://sso.passport.yandex.ru/push?uuid=ead76e2c-4e12-4d08-bd3d-52d358275133&retpath=https%3A%2F%2Fdzen.ru%2F%3Fis_autologin_ya%3Dtrue).
- http://zen.yandex.ru/ initial status: 302.
- Certificate: GlobalSign nv-sa GlobalSign GCC R46 OV TLS CA 2025, valid until 2027-01-25T20:59:59+00:00.
