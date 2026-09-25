# Security Audit Report — firstdata.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://firstdata.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | firstdata.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 7, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 6 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 7 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 8 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 9 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 10 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 11 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 14 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 15 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 16 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://firstdata.com/ without HttpOnly: PHPSESSID, __uzma, __uzmb, __uzmc, __uzmd. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://firstdata.com/ without Secure: __uzma, __uzmb, __uzmc, __uzmd. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://firstdata.com/ without SameSite=Lax/Strict: PHPSESSID, __uzma, __uzmb, __uzmc, __uzmd. Cross-site request cookies.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://firstdata.com/. Clients may connect over plain HTTP on first visit.

### 5. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://firstdata.com/; no defense-in-depth against XSS/content injection.

### 6. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://firstdata.com/; browsers may MIME-sniff responses.

### 7. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://firstdata.com/; page may be rendered in a foreign frame.

### 8. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for firstdata.com lists 20 name(s) besides the scope host: GetAssistance.Telecheck.com, Ignitepayments.ca, TRSRecoveryServices.com, carat.fiserv.com, franchise.fiserv.com, ignitepayments.com, merchants.fiserv.com, mex.clover.com... (3 no longer resolve)

### 9. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `talent.clover.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 10. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `www.cditechnology.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 11. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `www.ignitepayments.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://firstdata.com/; full URL (incl. query strings) is sent as referrer by default.

### 13. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://firstdata.com/; browser features (camera, mic, geolocation) unrestricted.

### 14. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://firstdata.com/ -> https://firstdata.com/ (positive check).

### 15. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on firstdata.com.

### 16. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://firstdata.com/ redirects to https://validate.perfdrive.com/64b926de080836ab9a2812de3f961c22/?ssa=76a131fe-fa01-49dc-9cd9-462bb753f3c8&ssb=83496297884&ssc=https%3A%2F%2Fmerchants.fiserv.com%2F&ssi=d59cc4f8-cskb-425f-b253-e9cc28e61872&ssk=botmanager_support@radware.com&ssm=87180341707991098106143663910860&ssn=b85f8b678cf1a8886d1610f95eb250d7fcb8d01a5817-2517-41ad-bab3b3&sso=1d9c762c-10f3fbd5ea05d575ebd60485e4ca892d61d508479a1156a5&ssp=14509491991790389747179031576641622&ssq=29997375111364446569251113035650749870402&ssr=MTE4LjE1MC4xMDguMjIx&sst=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/126.0.0.0%20Safari/537.36&ssu=&ssv=&ssw=&ssx=eyJfX3V6bWYiOiI3ZjkwMDBkMDFhNTgxNy0yNTE3LTQxYWQtYjYyYy0xMGYzZmJkNWVhMDUxLTE3OTAzNTExMTM4NzAwLTAwNTczYmUwMzkzN2I3OWE1MTAxMCJ9.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://firstdata.com/ final status: 200 (final URL https://validate.perfdrive.com/64b926de080836ab9a2812de3f961c22/?ssa=76a131fe-fa01-49dc-9cd9-462bb753f3c8&ssb=83496297884&ssc=https%3A%2F%2Fmerchants.fiserv.com%2F&ssi=d59cc4f8-cskb-425f-b253-e9cc28e61872&ssk=botmanager_support@radware.com&ssm=87180341707991098106143663910860&ssn=b85f8b678cf1a8886d1610f95eb250d7fcb8d01a5817-2517-41ad-bab3b3&sso=1d9c762c-10f3fbd5ea05d575ebd60485e4ca892d61d508479a1156a5&ssp=14509491991790389747179031576641622&ssq=29997375111364446569251113035650749870402&ssr=MTE4LjE1MC4xMDguMjIx&sst=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/126.0.0.0%20Safari/537.36&ssu=&ssv=&ssw=&ssx=eyJfX3V6bWYiOiI3ZjkwMDBkMDFhNTgxNy0yNTE3LTQxYWQtYjYyYy0xMGYzZmJkNWVhMDUxLTE3OTAzNTExMTM4NzAwLTAwNTczYmUwMzkzN2I3OWE1MTAxMCJ9).
- http://firstdata.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2027-01-20T23:59:59+00:00.
