# Security Audit Report — blogs.adobe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blogs.adobe.com/ |
| Bug bounty program | [Adobe](https://hackerone.com/adobe) |
| Listed scope domain | blogs.adobe.com |
| Test date | 2026-09-24 22:14 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **2** (High: 0, Medium: 1, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | T6 | Certificate hostname mismatch | CWE-297 |
| 2 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Certificate hostname mismatch (`T6`)

- **CWE:** CWE-297
- **Detail:** Server certificate for blogs.adobe.com is not valid for its hostname (certificate verify failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'blogs.adobe.com'. (_ssl.c:1010)).

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://blogs.adobe.com/: SSLError: HTTPSConnectionPool(host='blogs.adobe.com', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIF

## Reproduction notes

- Scanned 2026-09-24 22:14 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://blogs.adobe.com/ initial status: 500.
