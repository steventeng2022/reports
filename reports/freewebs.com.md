# Security Audit Report — freewebs.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://freewebs.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | freewebs.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 6, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 7 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 8 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 9 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 10 | info | H2c | HSTS not preloaded | CWE-319 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 13 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 14 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 15 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 16 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 17 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://freewebs.com/ without HttpOnly: cf-city, cf-ipcountry, cf-region-code, testUserId, vista-jdp, vp-bot-category, vp-bot-score, vp-bot-verified, vpauth, vpsession, vpsession-type. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://freewebs.com/ without Secure: testUserId. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://freewebs.com/ without SameSite=Lax/Strict: __cf_bm, cf-city, cf-ipcountry, cf-region-code, testUserId, vista-jdp, vp-bot-category, vp-bot-score, vp-bot-verified. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://freewebs.com/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://freewebs.com/; browsers may MIME-sniff responses.

### 6. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://freewebs.com/; page may be rendered in a foreign frame.

### 7. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond freewebs.com: vistaprint.com.

### 8. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for freewebs.com lists 1 name(s) besides the scope host: *.freewebs.com

### 9. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 10. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://freewebs.com/; full URL (incl. query strings) is sent as referrer by default.

### 12. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://freewebs.com/; browser features (camera, mic, geolocation) unrestricted.

### 13. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://freewebs.com/ lists 0 URLs.

### 14. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://freewebs.com/ -> https://www.vistaprint.com/digital-marketing/webs-shutdown (positive check).

### 15. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://freewebs.com/ exposes 0 unique Disallow path(s)

### 16. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://freewebs.com (191468 bytes)

### 17. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://freewebs.com/ redirects to https://www.vistaprint.com/digital-marketing/webs-shutdown.

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://freewebs.com/ final status: 200 (final URL https://www.vistaprint.com/digital-marketing/webs-shutdown).
- http://freewebs.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-14T23:50:56+00:00.
