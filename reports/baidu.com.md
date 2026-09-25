# Security Audit Report — baidu.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://baidu.com/ |
| Bug bounty program | [Baidu](https://bsrc.baidu.com/v2/#/en) |
| Listed scope domain | baidu.com |
| Test date | 2026-09-25 00:44 UTC |
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
- **Detail:** Certificate for baidu.com lists 52 name(s) besides the scope host: *.91.com, *.aipage.cn, *.aipage.com, *.apollo.auto, *.baidu.com, *.baidubce.com, *.baiducontent.com, *.baidupcs.com... (1 no longer resolve)

### 2. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `baifubao.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 3. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://baidu.com/: ReadTimeout: HTTPSConnectionPool(host='baidu.com', port=443): Read timed out. (read timeout=15)

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://baidu.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign RSA OV SSL CA 2018, valid until 2027-01-24T02:32:55+00:00.
