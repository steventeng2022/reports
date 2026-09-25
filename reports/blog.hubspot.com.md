# Security Audit Report — blog.hubspot.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blog.hubspot.com/ |
| Bug bounty program | [HubSpot](https://bugcrowd.com/hubspot) |
| Listed scope domain | blog.hubspot.com |
| Test date | 2026-09-25 02:55 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://blog.hubspot.com/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for blog.hubspot.com lists 1 name(s) besides the scope host: b8768f2b.sni.cloudflaressl.com

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://blog.hubspot.com/; browser features (camera, mic, geolocation) unrestricted.

### 4. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://blog.hubspot.com/ lists 2593 URLs.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://blog.hubspot.com/ -> https://blog.hubspot.com/ (positive check).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://blog.hubspot.com/ exposes 79 unique Disallow path(s) (*/agency/author/*&, */agency/author/*?, */author/*&, */author/*?, */customers/author/*&) and 1 sitemap reference(s)

### 7. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://blog.hubspot.com (1297 bytes); contact: mailto:security-notifications@hubspot.com

## Reproduction notes

- Scanned 2026-09-25 02:55 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://blog.hubspot.com/ final status: 200 (final URL https://blog.hubspot.com/).
- http://blog.hubspot.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-24T22:07:49+00:00.
