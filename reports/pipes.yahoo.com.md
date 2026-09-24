# Security Audit Report — pipes.yahoo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pipes.yahoo.com/ |
| Bug bounty program | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| Listed scope domain | pipes.yahoo.com |
| Test date | 2026-09-24 22:14 UTC |
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
- **Detail:** pipes.yahoo.com returned no A/AAAA record.

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://pipes.yahoo.com/: ConnectionError: HTTPSConnectionPool(host='pipes.yahoo.com', port=443): Max retries exceeded with url: / (Caused by NameResolutionError("HTTPSConnection(host='pipes.yahoo.com', 

## Reproduction notes

- Scanned 2026-09-24 22:14 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
