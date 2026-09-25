# Security Audit Report — en.advertisercommunity.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://en.advertisercommunity.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | en.advertisercommunity.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 1, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | H2c | HSTS not preloaded | CWE-319 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 11 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 13 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 14 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://en.advertisercommunity.com/ without SameSite=Lax/Strict: NID. Cross-site request cookies.

### 2. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond en.advertisercommunity.com: .google.com.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for en.advertisercommunity.com lists 327 name(s) besides the scope host: *.abc.xyz, *.adsensecustomsearchads.com, *.advertisercommunity.com, *.aiplatform-notebook.cloud.google.com, *.aiplatform-training.cloud.google.com, *.ampcache.com, *.ampproject.com, *.ampproject.net... (10 no longer resolve)

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `ampcache.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `cloud.google` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `floonet.goog` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubdomains` lacks the preload directive.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://en.advertisercommunity.com/; full URL (incl. query strings) is sent as referrer by default.

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://en.advertisercommunity.com/; browser features (camera, mic, geolocation) unrestricted.

### 10. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://en.advertisercommunity.com/ lists 0 URLs.

### 11. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://en.advertisercommunity.com/ -> https://support.google.com/google-ads/community?ctx=lithium (positive check).

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://en.advertisercommunity.com/ exposes 7 unique Disallow path(s) (/*/api, /*/apis, /*/bin/search.py, /*/forum-attachment, /*/search)

### 13. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://en.advertisercommunity.com (301307 bytes)

### 14. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://en.advertisercommunity.com/ redirects to https://support.google.com/google-ads/community?ctx=lithium.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://en.advertisercommunity.com/ final status: 200 (final URL https://support.google.com/google-ads/community?ctx=lithium).
- http://en.advertisercommunity.com/ initial status: 301.
- Certificate: Google Trust Services WR2, valid until 2026-12-03T19:22:22+00:00.
