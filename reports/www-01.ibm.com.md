# Security Audit Report — www-01.ibm.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://www-01.ibm.com/ |
| Bug bounty program | [IBM](https://hackerone.com/ibm) |
| Listed scope domain | www-01.ibm.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 9 | info | H2c | HSTS not preloaded | CWE-319 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 14 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 15 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://www-01.ibm.com/ without HttpOnly: bm_sz. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://www-01.ibm.com/ without Secure: bm_sz. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://www-01.ibm.com/ without SameSite=Lax/Strict: bm_sz. Cross-site request cookies.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for www-01.ibm.com lists 64 name(s) besides the scope host: 1.cms.s81c.com, 1.cmsnew.s81c.com, 1.cmspoc.s81c.com, 1.cmsstage.s81c.com, 1.cmsstagenew.s81c.com, 1.cmstest.s81c.com, 1.dam.s81c.com, 1.damstage.s81c.com... (12 no longer resolve)

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `1.cms.s81c.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `1.cmsnew.s81c.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `1.cmspoc.s81c.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 8. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 9. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://www-01.ibm.com/; full URL (incl. query strings) is sent as referrer by default.

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://www-01.ibm.com/; browser features (camera, mic, geolocation) unrestricted.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://www-01.ibm.com/ -> https://www-01.ibm.com/ (positive check).

### 13. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://www-01.ibm.com/ exposes 74 unique Disallow path(s) (/, /*.ssi$, //, /Admin, /SametimeWebApp) and 5 sitemap reference(s)

### 14. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://www-01.ibm.com (376 bytes); contact: https://www.ibm.com/trust/security-psirt

### 15. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://www-01.ibm.com/ redirects to https://www.ibm.com/us-en.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://www-01.ibm.com/ final status: 200 (final URL https://www.ibm.com/us-en).
- http://www-01.ibm.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2027-01-05T23:59:59+00:00.
