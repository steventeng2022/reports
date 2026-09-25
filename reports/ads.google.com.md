# Security Audit Report — ads.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ads.google.com/ |
| Bug bounty program | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| Listed scope domain | ads.google.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 0, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 3 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 9 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for ads.google.com lists 120 name(s) besides the scope host: *.admob.biz, *.admob.co.in, *.admob.co.kr, *.admob.co.nz, *.admob.co.uk, *.admob.co.za, *.admob.com, *.admob.com.br... (1 no longer resolve)

### 2. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `frame.ads.google.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 3. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://ads.google.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://ads.google.com/ -> https://ads.google.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://ads.google.com/ exposes 2 unique Disallow path(s) (/, /api*?hl=)

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on ads.google.com.

### 9. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://ads.google.com/ redirects to https://business.google.com/tw/google-ads/.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://ads.google.com/ final status: 200 (final URL https://business.google.com/tw/google-ads/).
- http://ads.google.com/ initial status: 301.
- Certificate: Google Trust Services WR2, valid until 2026-12-03T19:23:17+00:00.
