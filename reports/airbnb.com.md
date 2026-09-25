# Security Audit Report — airbnb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://airbnb.com/ |
| Bug bounty program | [Airbnb](https://hackerone.com/airbnb) |
| Listed scope domain | airbnb.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 7, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 7 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 8 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 13 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 14 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://airbnb.com/ without HttpOnly: bev, country, everest_cookie. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://airbnb.com/ without SameSite=Lax/Strict: bev, country, everest_cookie. Cross-site request cookies.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://airbnb.com/. Clients may connect over plain HTTP on first visit.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://airbnb.com/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://airbnb.com/; browsers may MIME-sniff responses.

### 6. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://airbnb.com/; page may be rendered in a foreign frame.

### 7. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-22T23:59:59+00:00 (27 days left) for airbnb.com.

### 8. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for airbnb.com lists 77 name(s) besides the scope host: airbnb.ae, airbnb.al, airbnb.am, airbnb.at, airbnb.az, airbnb.ba, airbnb.be, airbnb.ca...

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://airbnb.com/; full URL (incl. query strings) is sent as referrer by default.

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://airbnb.com/; browser features (camera, mic, geolocation) unrestricted.

### 11. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://airbnb.com/ -> https://airbnb.com/ (positive check).

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://airbnb.com/ exposes 66 unique Disallow path(s) (/, /*/skeleton, /*/stays/, /*/sw_skeleton, /*/things-to-do) and 1 sitemap reference(s)

### 13. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://airbnb.com (271 bytes); contact: https://hackerone.com/airbnb/

### 14. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://airbnb.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://airbnb.com/ final status: 403 (final URL https://www.airbnb.com/).
- http://airbnb.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2026-10-22T23:59:59+00:00.
