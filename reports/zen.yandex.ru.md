# Security Audit Report — zen.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zen.yandex.ru/ |
| Bug bounty program | [Yandex](https://yandex.com/bugbounty/index) |
| Listed scope domain | zen.yandex.ru |
| Test date | 2026-09-25 19:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 0, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 3 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for zen.yandex.ru lists 46 name(s) besides the scope host: *.zen.yandex.com, *.zen.yandex.ru, dzen.ya.ru, dzen.yandex.ru, main.zdevx.yandex.ru, www.zen.yandex.az, www.zen.yandex.by, www.zen.yandex.co.il... (1 no longer resolve)

### 2. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `main.zdevx.yandex.ru` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 3. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://zen.yandex.ru/: ConnectionError: ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))

## Reproduction notes

- Scanned 2026-09-25 19:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://zen.yandex.ru/ initial status: 302.
- Certificate: GlobalSign nv-sa GlobalSign GCC R46 OV TLS CA 2025, valid until 2027-01-25T20:59:59+00:00.
