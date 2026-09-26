# Security Audit Report — surveymonkey.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://surveymonkey.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | surveymonkey.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | H2c | HSTS not preloaded | CWE-319 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://surveymonkey.com/ without HttpOnly: AMP_beb2473154, attr_multitouch, cdp_seg, ep201, ep202. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://surveymonkey.com/ without SameSite=Lax/Strict: AMP_beb2473154, attr_multitouch, cdp_seg, ep201, ep202, ep203. Cross-site request cookies.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for surveymonkey.com lists 30 name(s) besides the scope host: *.ca.research.net, *.eu.research.net, *.eu.surveymonkey.com, *.eu.surveymonkey.net, *.feedbackeconomy.com, *.research.net, *.smassets.net, *.surveymonkey.ca... (2 no longer resolve)

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `feedbackeconomy.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `smassets.net` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://surveymonkey.com/; browser features (camera, mic, geolocation) unrestricted.

### 8. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://surveymonkey.com/ lists 18 URLs.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://surveymonkey.com/ -> https://surveymonkey.com/ (positive check).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://surveymonkey.com/ exposes 21 unique Disallow path(s) (/*?query=, /*?usecase=, /apis/v3/internal/intents, /billing/confirmed, /billing/invoice*) and 1 sitemap reference(s)

### 11. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on surveymonkey.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://surveymonkey.com/ final status: 200 (final URL https://www.surveymonkey.com/).
- http://surveymonkey.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2026-11-26T23:59:59+00:00.
