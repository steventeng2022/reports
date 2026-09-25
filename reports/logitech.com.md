# Security Audit Report — logitech.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://logitech.com/ |
| Bug bounty program | [Logitech](https://hackerone.com/logitech) |
| Listed scope domain | logitech.com |
| Test date | 2026-09-25 13:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 1, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://logitech.com/; no defense-in-depth against XSS/content injection.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for logitech.com lists 14 name(s) besides the scope host: *.logicool.co.jp, *.logitech.com, *.logitech.com.cn, *.logitech.fr, *.logitechg.com, *.logitechg.com.cn, *.logitechg.fr, logicool.co.jp...

### 3. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://logitech.com/ lists 735 URLs.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://logitech.com/ -> https://logitech.com:443/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://logitech.com/ exposes 15 unique Disallow path(s) (/*/cart, /*/checkout, /*/product-refs/, /*/refs/, /_app/) and 2 sitemap reference(s)

### 6. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://logitech.com (196 bytes); contact: https://www.logitech.com/security

## Reproduction notes

- Scanned 2026-09-25 13:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://logitech.com/ final status: 200 (final URL https://www.logitech.com/zh-tw).
- http://logitech.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2026-12-11T23:59:59+00:00.
