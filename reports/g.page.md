# Security Audit Report — g.page

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://g.page/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | g.page |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 0, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 3 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 6 | info | H2c | HSTS not preloaded | CWE-319 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 12 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for g.page lists 327 name(s) besides the scope host: *.abc.xyz, *.adsensecustomsearchads.com, *.advertisercommunity.com, *.aiplatform-notebook.cloud.google.com, *.aiplatform-training.cloud.google.com, *.ampcache.com, *.ampproject.com, *.ampproject.net... (10 no longer resolve)

### 2. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `ampcache.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 3. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `cloud.google` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `floonet.goog` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 6. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://g.page/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://g.page/ lists 0 URLs.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://g.page/ -> https://g.page/ (positive check).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://g.page/ exposes 0 unique Disallow path(s)

### 11. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on g.page.

### 12. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://g.page/ redirects to https://business.google.com/tw/business-profile/?ppsrc=GPDA2.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://g.page/ final status: 200 (final URL https://business.google.com/tw/business-profile/?ppsrc=GPDA2).
- http://g.page/ initial status: 301.
- Certificate: Google Trust Services WE2, valid until 2026-12-03T19:22:33+00:00.
