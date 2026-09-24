# Security Audit Report — cyber.law.harvard.edu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cyber.law.harvard.edu/ |
| Bug bounty program | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| Listed scope domain | cyber.law.harvard.edu |
| Test date | 2026-09-24 22:14 UTC |
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
- **Detail:** Certificate for cyber.law.harvard.edu lists 18 name(s) besides the scope host: adam.law.harvard.edu, berkman.harvard.edu, blogs.harvard.edu, blogs.law.harvard.edu, brk.mn, cyber.harvard.edu, dev.herdict.org, herdict.org...

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://cyber.law.harvard.edu/: ReadTimeout: HTTPSConnectionPool(host='cyber.law.harvard.edu', port=443): Read timed out. (read timeout=15)

## Reproduction notes

- Scanned 2026-09-24 22:14 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://cyber.law.harvard.edu/ initial status: 301.
- Certificate: Let's Encrypt YR2, valid until 2026-11-12T12:47:26+00:00.
