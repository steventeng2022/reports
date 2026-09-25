# Security Audit Report — photos.app.goo.gl

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://photos.app.goo.gl/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | photos.app.goo.gl |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | X2 | HTTPS homepage returned HTTP 400 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://photos.app.goo.gl/. Clients may connect over plain HTTP on first visit.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for photos.app.goo.gl lists 328 name(s) besides the scope host: *.abc.xyz, *.adsensecustomsearchads.com, *.advertisercommunity.com, *.aiplatform-notebook.cloud.google.com, *.aiplatform-training.cloud.google.com, *.ampcache.com, *.ampproject.com, *.ampproject.net... (10 no longer resolve)

### 3. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `ampcache.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `cloud.google` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `floonet.goog` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://photos.app.goo.gl/; full URL (incl. query strings) is sent as referrer by default.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://photos.app.goo.gl/ -> https://photos.app.goo.gl/ (positive check).

### 8. [INFO] HTTPS homepage returned HTTP 400 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://photos.app.goo.gl/ responded 400 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://photos.app.goo.gl/ final status: 400 (final URL https://photos.app.goo.gl/).
- http://photos.app.goo.gl/ initial status: 301.
- Certificate: Google Trust Services WE2, valid until 2026-12-03T19:22:33+00:00.
