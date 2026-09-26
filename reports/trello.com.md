# Security Audit Report — trello.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://trello.com/ |
| Bug bounty program | [Trello](https://bugcrowd.com/trello) |
| Listed scope domain | trello.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 3, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 11 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 13 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://trello.com/ without HttpOnly: ajs_anonymous_id, atlCohort, bxp_gateway_anchor. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://trello.com/ without SameSite=Lax/Strict: ajs_anonymous_id, atlCohort, bxp_gateway_anchor. Cross-site request cookies.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://trello.com/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for trello.com lists 53 name(s) besides the scope host: *.apkg.io, *.atl-paas.net, *.atlassian-3p.com, *.atlassian-isolated-3p.com, *.atlassian.com, *.atlassian.dev, *.bitbucket.com, *.bitbucket.io... (2 no longer resolve)

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `apkg.io` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `atlassian.dev` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=63072000; preload` does not cover subdomains.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://trello.com/; full URL (incl. query strings) is sent as referrer by default.

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://trello.com/; browser features (camera, mic, geolocation) unrestricted.

### 10. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://trello.com/ lists 0 URLs.

### 11. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://trello.com/ -> https://trello.com/ (positive check).

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://trello.com/ exposes 23 unique Disallow path(s) (*/add-card?, */login?, */signup?, /1/, /associate/) and 1 sitemap reference(s)

### 13. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://trello.com (1448 bytes); contact: https://www.atlassian.com/trust/security/report-a-vulnerability

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://trello.com/ final status: 200 (final URL https://trello.com/).
- http://trello.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2027-02-09T23:59:59+00:00.
