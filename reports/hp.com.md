# Security Audit Report — hp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hp.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | hp.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 6, Info: 13)

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
| 9 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 10 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 11 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 12 | info | H2 | Short HSTS max-age | CWE-319 |
| 13 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 14 | info | H2c | HSTS not preloaded | CWE-319 |
| 15 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 16 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 17 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 18 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 19 | info | X2 | HTTPS homepage returned HTTP 404 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://hp.com/ without HttpOnly: aka_client_code, c_hp_filter. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://hp.com/ without Secure: aka_client_code. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://hp.com/ without SameSite=Lax/Strict: aka_client_code, c_hp_filter. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://hp.com/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://hp.com/; browsers may MIME-sniff responses.

### 6. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://hp.com/; page may be rendered in a foreign frame.

### 7. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond hp.com: .www.hp.com.

### 8. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for hp.com lists 96 name(s) besides the scope host: 123.hp.com, h20545.www2.hp.com, h30167.www3.hp.com, hp.am, hp.be, hp.ca, hp.cg, hp.cl... (6 no longer resolve)

### 9. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `twitterhp.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 10. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `www.touchsmartprinter.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 11. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `www.touchsmartprinters.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 12. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=600 (< 1 year): `max-age=600`.

### 13. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=600` does not cover subdomains.

### 14. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=600` lacks the preload directive.

### 15. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://hp.com/; full URL (incl. query strings) is sent as referrer by default.

### 16. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://hp.com/; browser features (camera, mic, geolocation) unrestricted.

### 17. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://hp.com/ -> https://hp.com/ (positive check).

### 18. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on hp.com.

### 19. [INFO] HTTPS homepage returned HTTP 404 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://hp.com/ responded 404 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://hp.com/ final status: 404 (final URL https://www.hp.com/).
- http://hp.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2027-01-30T23:59:59+00:00.
