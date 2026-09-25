# Security Audit Report — gov.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gov.uk/ |
| Bug bounty program | [NCSC UK](https://hackerone.com/ncsc_uk) |
| Listed scope domain | gov.uk |
| Test date | 2026-09-25 06:31 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 3 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for gov.uk lists 12 name(s) besides the scope host: *.businesslink.gov.uk, *.cabinet-office.gov.uk, *.direct.gov.uk, *.publishing.service.gov.uk, api.gov.uk, assets.digital.cabinet-office.gov.uk, cabinet-office.gov.uk, data.gov.uk...

### 2. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; preload` does not cover subdomains.

### 3. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://gov.uk/ lists 35 URLs.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://gov.uk/ -> https://gov.uk/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://gov.uk/ exposes 3 unique Disallow path(s) (/, /*/print$, /search/all*) and 1 sitemap reference(s)

### 6. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://gov.uk (447 bytes); contact: https://hackerone.com/44c348eb-e030-4273-b445-d4a2f6f83ba8/embedded_submissions/new

## Reproduction notes

- Scanned 2026-09-25 06:31 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://gov.uk/ final status: 200 (final URL https://www.gov.uk/).
- http://gov.uk/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign RSA OV SSL CA 2018, valid until 2026-12-28T22:06:14+00:00.
