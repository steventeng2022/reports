# Security Audit Report — stripe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stripe.com/ |
| Bug bounty program | [Stripe](https://hackerone.com/stripe) |
| Listed scope domain | stripe.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 0, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for stripe.com lists 1 name(s) besides the scope host: www.stripe.com

### 2. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://stripe.com/; browser features (camera, mic, geolocation) unrestricted.

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://stripe.com/ -> https://stripe.com/ (positive check).

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://stripe.com/ exposes 10 unique Disallow path(s) (/bitcoin/refund, /docs, /docs$, /handoff, /handoff-healthcheck) and 1 sitemap reference(s)

### 5. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://stripe.com (285 bytes); contact: https://hackerone.com/stripe

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://stripe.com/ final status: 200 (final URL https://stripe.com/).
- http://stripe.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G3 TLS ECC SHA384 2020 CA1, valid until 2026-11-12T23:59:59+00:00.
