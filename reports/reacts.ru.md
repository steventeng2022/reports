# Security Audit Report — reacts.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://reacts.ru/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | reacts.ru |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **2** (High: 0, Medium: 1, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | T5 | Certificate chain verification failure | CWE-298 |
| 2 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Certificate chain verification failure (`T5`)

- **CWE:** CWE-298
- **Detail:** certificate verify failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1010) for reacts.ru.

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://reacts.ru/: SSLError: HTTPSConnectionPool(host='reacts.ru', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAIL

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://reacts.ru/ initial status: 200.
