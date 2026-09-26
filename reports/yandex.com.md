# Security Audit Report — yandex.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yandex.com/ |
| Bug bounty program | [Yandex](https://yandex.com/bugbounty/index) |
| Listed scope domain | yandex.com |
| Test date | 2026-09-25 19:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 0, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for yandex.com lists 51 name(s) besides the scope host: *.xn--d1acpjx3f.xn--p1ai, *.ya.ru, *.yandex.aero, *.yandex.az, *.yandex.by, *.yandex.co.il, *.yandex.com, *.yandex.com.am...

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://yandex.com/: ReadTimeout: HTTPSConnectionPool(host='yandex.com', port=443): Read timed out. (read timeout=15)

## Reproduction notes

- Scanned 2026-09-25 19:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://yandex.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign ECC OV SSL CA 2018, valid until 2026-12-29T20:59:59+00:00.
