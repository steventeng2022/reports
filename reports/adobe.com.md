# Security Audit Report — adobe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://adobe.com/ |
| Bug bounty program | [Adobe](https://hackerone.com/adobe) |
| Listed scope domain | adobe.com |
| Test date | 2026-09-25 09:51 UTC |
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
- **Detail:** Certificate for adobe.com lists 1 name(s) besides the scope host: *.adobe.com

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://adobe.com/: ReadTimeout: HTTPSConnectionPool(host='www.adobe.com', port=443): Read timed out. (read timeout=15)

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://adobe.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G3 TLS ECC SHA384 2020 CA1, valid until 2027-01-04T23:59:59+00:00.
