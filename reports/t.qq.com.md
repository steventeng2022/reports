# Security Audit Report — t.qq.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://t.qq.com/ |
| Bug bounty program | [Tencent](https://en.security.tencent.com) |
| Listed scope domain | t.qq.com |
| Test date | 2026-09-25 13:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 0, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D0 | Scope host does not resolve in DNS | CWE-200 |
| 2 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [INFO] Scope host does not resolve in DNS (`D0`)

- **CWE:** CWE-200
- **Detail:** t.qq.com returned no A/AAAA record.

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://t.qq.com/: ConnectionError: HTTPSConnectionPool(host='t.qq.com', port=443): Max retries exceeded with url: / (Caused by NameResolutionError("HTTPSConnection(host='t.qq.com', port=443): Fai

## Reproduction notes

- Scanned 2026-09-25 13:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
