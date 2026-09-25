# Security Audit Report — blog.livedoor.jp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blog.livedoor.jp/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | blog.livedoor.jp |
| Test date | 2026-09-25 02:55 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **2** (High: 0, Medium: 1, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | T4 | Self-signed TLS certificate | CWE-295 |
| 2 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Self-signed TLS certificate (`T4`)

- **CWE:** CWE-295
- **Detail:** Certificate for blog.livedoor.jp is self-signed (certificate verify failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1010)). Browsers will warn unless the CA is trusted.

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://blog.livedoor.jp/: SSLError: HTTPSConnectionPool(host='blog.livedoor.jp', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERI

## Reproduction notes

- Scanned 2026-09-25 02:55 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://blog.livedoor.jp/ initial status: 200.
