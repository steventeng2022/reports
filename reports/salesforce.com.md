# Security Audit Report — salesforce.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://salesforce.com/ |
| Bug bounty program | [Salesforce](https://www.salesforce.com/company/disclosure/) |
| Listed scope domain | salesforce.com |
| Test date | 2026-09-26 01:40 UTC |
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
| 7 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 8 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 9 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 10 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 11 | info | H2 | Short HSTS max-age | CWE-319 |
| 12 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 13 | info | H2c | HSTS not preloaded | CWE-319 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 15 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 16 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 17 | info | R1 | robots.txt protected | CWE-200 |
| 18 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 19 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://salesforce.com/ without HttpOnly: ak_loc. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://salesforce.com/ without Secure: ak_loc. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://salesforce.com/ without SameSite=Lax/Strict: AKA_A2, ak_loc. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://salesforce.com/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://salesforce.com/; browsers may MIME-sniff responses.

### 6. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://salesforce.com/; page may be rendered in a foreign frame.

### 7. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for salesforce.com lists 68 name(s) besides the scope host: agentblazer.com, askmoreof.ai, askmoreofai.com, assistly.com, atonit.com.br, atonit.digital, attic.io, buddymedia.com... (4 no longer resolve)

### 8. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `chatter.salesforce.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 9. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `govforce.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 10. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `sfdcstatic.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 11. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=86400 (< 1 year): `max-age=86400`.

### 12. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=86400` does not cover subdomains.

### 13. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=86400` lacks the preload directive.

### 14. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://salesforce.com/; full URL (incl. query strings) is sent as referrer by default.

### 15. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://salesforce.com/; browser features (camera, mic, geolocation) unrestricted.

### 16. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://salesforce.com/ -> https://salesforce.com/ (positive check).

### 17. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 18. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on salesforce.com.

### 19. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://salesforce.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://salesforce.com/ final status: 403 (final URL https://www.salesforce.com/).
- http://salesforce.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2027-04-09T23:59:59+00:00.
