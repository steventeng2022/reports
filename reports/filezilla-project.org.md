# Security Audit Report — filezilla-project.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://filezilla-project.org/ |
| Bug bounty program | [FileZilla](https://hackerone.com/filezilla) |
| Listed scope domain | filezilla-project.org |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://filezilla-project.org/: ConnectTimeout: HTTPSConnectionPool(host='filezilla-project.org', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='filezilla-pr

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
