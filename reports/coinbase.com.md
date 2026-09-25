# Security Audit Report — coinbase.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://coinbase.com/ |
| Bug bounty program | [Coinbase](https://hackerone.com/coinbase) |
| Listed scope domain | coinbase.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 0, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 3 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 4 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 5 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for coinbase.com lists 1 name(s) besides the scope host: *.cdp.coinbase.com

### 2. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://coinbase.com/ -> https://coinbase.com/ (positive check).

### 3. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://coinbase.com/ exposes 21 unique Disallow path(s) (/*/*/cookie-preferences, /*/advanced-trade/spot/, /*/converter/*/*?currencyPage*, /*/cookie-preferences, /*/join/) and 15 sitemap reference(s)

### 4. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://coinbase.com (117 bytes); contact: https://hackerone.com/coinbase

### 5. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://coinbase.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://coinbase.com/ final status: 403 (final URL https://www.coinbase.com/).
- http://coinbase.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-20T02:34:19+00:00.
