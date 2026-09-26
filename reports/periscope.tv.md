# Security Audit Report — periscope.tv

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://periscope.tv/ |
| Bug bounty program | [Twitter](https://hackerone.com/twitter) |
| Listed scope domain | periscope.tv |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://periscope.tv/ without SameSite=Lax/Strict: pscp-csrf. Cross-site request cookies.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for periscope.tv lists 1 name(s) besides the scope host: *.periscope.tv

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://periscope.tv/; browser features (camera, mic, geolocation) unrestricted.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://periscope.tv/ -> https://periscope.tv/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://periscope.tv/ exposes 4 unique Disallow path(s) (/android-attribution, /eula.html, /ios-attribution, /privacy.html)

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://periscope.tv/ final status: 200 (final URL https://www.periscope.tv/).
- http://periscope.tv/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M01, valid until 2027-02-10T23:59:59+00:00.
