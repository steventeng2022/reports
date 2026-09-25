# Security Audit Report — coinmarketcap.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://coinmarketcap.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | coinmarketcap.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H2c | HSTS not preloaded | CWE-319 |
| 3 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for coinmarketcap.com lists 6 name(s) besides the scope host: *.beta.coinmarketcap.com, *.cmc.ai, *.cmcap.io, *.coinmarketcap.com, *.staging.coinmarketcap.com, cmc.ai

### 2. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubdomains` lacks the preload directive.

### 3. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://coinmarketcap.com/ lists 27 URLs.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://coinmarketcap.com/ -> https://coinmarketcap.com/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://coinmarketcap.com/ exposes 12 unique Disallow path(s) (/*/headlines/*, /community/*/coins/*, /community/*/live/*, /community/*/post/*, /community/*/profile/*) and 9 sitemap reference(s)

### 6. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on coinmarketcap.com.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://coinmarketcap.com/ final status: 200 (final URL https://coinmarketcap.com/).
- http://coinmarketcap.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-01-12T23:59:59+00:00.
