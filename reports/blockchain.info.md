# Security Audit Report — blockchain.info

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blockchain.info/ |
| Bug bounty program | [Blockchain](https://hackerone.com/blockchain) |
| Listed scope domain | blockchain.info |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 0, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 6 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |
| 7 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for blockchain.info lists 6 name(s) besides the scope host: api.blockchain.com, api.blockchain.info, bps.blockchain.com, login.blockchain.com, ws.blockchain.info, www.blockchain.com

### 2. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://blockchain.info/ lists 120 URLs.

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://blockchain.info/ -> https://blockchain.info/ (positive check).

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://blockchain.info/ exposes 6 unique Disallow path(s) (/*/block-index/*, /*/search, /*/tx-index/*, /r?*, /search) and 1 sitemap reference(s)

### 5. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://blockchain.info (216 bytes); contact: https://hackerone.com/blockchain

### 6. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://blockchain.info/ responded 403 (passive check only; no further probing).

### 7. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://blockchain.info/ redirects to https://www.blockchain.com/explorer.

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://blockchain.info/ final status: 403 (final URL https://www.blockchain.com/explorer).
- http://blockchain.info/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2026-10-26T23:59:59+00:00.
