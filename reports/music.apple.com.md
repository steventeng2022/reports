# Security Audit Report — music.apple.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://music.apple.com/ |
| Bug bounty program | [Apple](https://security.apple.com) |
| Listed scope domain | music.apple.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 0, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 3 | info | H2c | HSTS not preloaded | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for music.apple.com lists 70 name(s) besides the scope host: a1.mzstatic.com, a2.mzstatic.com, a3.mzstatic.com, a4.mzstatic.com, a5.mzstatic.com, accertify.mzstatic.com, amp-api-edge.apps.apple.com, amp-api-edge.music.apple.com... (1 no longer resolve)

### 2. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `edge.itunes.apple.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 3. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains, max-age=31536000; includeSubDomains` lacks the preload directive.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://music.apple.com/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://music.apple.com/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://music.apple.com/ -> https://music.apple.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://music.apple.com/ exposes 5 unique Disallow path(s) (*/search?*, /WebObjects/*, /api/*, /includes/*, /v1/*) and 10 sitemap reference(s)

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://music.apple.com (4101 bytes)

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://music.apple.com/ final status: 200 (final URL https://music.apple.com/us/new).
- http://music.apple.com/ initial status: 301.
- Certificate: Apple Inc. Apple Public EV Server RSA CA 1 - G1, valid until 2027-01-07T19:46:05+00:00.
