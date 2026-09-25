# Security Audit Report — messenger.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://messenger.com/ |
| Bug bounty program | [Facebook](https://www.facebook.com/whitehat) |
| Listed scope domain | messenger.com |
| Test date | 2026-09-25 04:28 UTC |
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
- **Detail:** Certificate expires 2026-10-02T23:59:59+00:00 (7 days left) for messenger.com.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for messenger.com lists 10 name(s) besides the scope host: *.facebook.com, *.facebook.net, *.fbcdn.net, *.fbsbx.com, *.m.facebook.com, *.messenger.com, *.xx.fbcdn.net, *.xy.fbcdn.net...

### 3. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://messenger.com/: ConnectionError: HTTPSConnectionPool(host='www.messenger.com', port=443): Max retries exceeded with url: / (Caused by NameResolutionError("HTTPSConnection(host='www.messenger.co

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://messenger.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2026-10-02T23:59:59+00:00.
