# Security Audit Report — t.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://t.me/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | t.me |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 9 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://t.me/ without SameSite=Lax/Strict: stel_ssid. Cross-site request cookies.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://t.me/; no defense-in-depth against XSS/content injection.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://t.me/; browsers may MIME-sniff responses.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for t.me lists 1 name(s) besides the scope host: *.t.me

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://t.me/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://t.me/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://t.me/ -> https://t.me/ (positive check).

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://t.me (19863 bytes)

### 9. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://t.me/ redirects to https://telegram.org/.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://t.me/ final status: 200 (final URL https://telegram.org/).
- http://t.me/ initial status: 301.
- Certificate: GoDaddy.com, Inc. Go Daddy Secure Certificate Authority - G2, valid until 2026-11-22T19:17:28+00:00.
