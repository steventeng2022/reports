# Security Audit Report — united.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://united.com/ |
| Bug bounty program | [United Airlines](https://bugcrowd.com/united-vdp) |
| Listed scope domain | united.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 5, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 9 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 10 | info | H2 | Short HSTS max-age | CWE-319 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 13 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 14 | info | R1 | robots.txt protected | CWE-200 |
| 15 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 16 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://united.com/ without HttpOnly: PROrigin, akacd_NS_AB. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://united.com/ without Secure: PROrigin. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://united.com/ without SameSite=Lax/Strict: PROrigin, akacd_NS_AB. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://united.com/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://united.com/; browsers may MIME-sniff responses.

### 6. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for united.com lists 20 name(s) besides the scope host: beta.united.com, checkin.united.com, ife.unitedwifi.com, mobile.united.com, pss.united.com, ual.com, unitedairlines.ca, unitedairlines.co.uk... (5 no longer resolve)

### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `ual.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 8. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `unitedairlines.ca` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 9. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `unitedairlines.co.uk` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 10. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=15768000 (< 1 year): `max-age=15768000; includeSubDomains; preload`.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://united.com/; full URL (incl. query strings) is sent as referrer by default.

### 12. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://united.com/; browser features (camera, mic, geolocation) unrestricted.

### 13. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://united.com/ -> https://united.com/ (positive check).

### 14. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 15. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on united.com.

### 16. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://united.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://united.com/ final status: 403 (final URL https://www.united.com/).
- http://united.com/ initial status: 301.
- Certificate: DigiCert Inc GeoTrust TLS RSA CA G1, valid until 2026-12-08T23:59:59+00:00.
