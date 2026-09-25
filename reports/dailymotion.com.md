# Security Audit Report — dailymotion.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dailymotion.com/ |
| Bug bounty program | [Dailymotion](https://yeswehack.com/programs/dailymotion-public-bug-bounty) |
| Listed scope domain | dailymotion.com |
| Test date | 2026-09-25 06:31 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 1, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-25T23:59:59+00:00 (30 days left) for dailymotion.com.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for dailymotion.com lists 1 name(s) besides the scope host: *.dailymotion.com

### 3. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://dailymotion.com/: ReadTimeout: HTTPSConnectionPool(host='dailymotion.com', port=443): Read timed out. (read timeout=15)

## Reproduction notes

- Scanned 2026-09-25 06:31 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://dailymotion.com/ initial status: 301.
- Certificate: ZeroSSL GmbH ZeroSSL RSA DV SSL CA 2, valid until 2026-10-25T23:59:59+00:00.
