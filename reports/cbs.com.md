# Security Audit Report — cbs.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cbs.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | cbs.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://cbs.com/: ConnectTimeout: HTTPSConnectionPool(host='www.cbs.com', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='www.cbs.com', port=443

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://cbs.com/ initial status: 301.
- Certificate: Let's Encrypt YE1, valid until 2026-12-07T00:46:32+00:00.
