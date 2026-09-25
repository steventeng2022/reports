# Security Audit Report — cnbc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cnbc.com/ |
| Bug bounty program | Nasdaq |
| Listed scope domain | cnbc.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 5, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 7 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 11 | info | R1 | robots.txt protected | CWE-200 |
| 12 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 13 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://cnbc.com/ without HttpOnly: akaas_CNBC_AudienceSegmentation, region. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://cnbc.com/ without Secure: region. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://cnbc.com/ without SameSite=Lax/Strict: akaas_CNBC_AudienceSegmentation, region. Cross-site request cookies.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://cnbc.com/. Clients may connect over plain HTTP on first visit.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://cnbc.com/; browsers may MIME-sniff responses.

### 6. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond cnbc.com: .www.cnbc.com.

### 7. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for cnbc.com lists 1 name(s) besides the scope host: *.cnbc.com

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://cnbc.com/; full URL (incl. query strings) is sent as referrer by default.

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://cnbc.com/; browser features (camera, mic, geolocation) unrestricted.

### 10. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://cnbc.com/ -> https://www.cnbc.com (positive check).

### 11. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 12. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on cnbc.com.

### 13. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://cnbc.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://cnbc.com/ final status: 403 (final URL https://www.cnbc.com).
- http://cnbc.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2027-02-10T23:59:59+00:00.
