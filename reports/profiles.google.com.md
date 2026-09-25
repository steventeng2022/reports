# Security Audit Report — profiles.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://profiles.google.com/ |
| Bug bounty program | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| Listed scope domain | profiles.google.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 3, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 8 | info | X2 | HTTPS homepage returned HTTP 404 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://profiles.google.com/ without SameSite=Lax/Strict: NID. Cross-site request cookies.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://profiles.google.com/. Clients may connect over plain HTTP on first visit.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://profiles.google.com/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for profiles.google.com lists 65 name(s) besides the scope host: *.aistudio.google.com, *.android.com, *.appengine.google.com, *.bdn.dev, *.cloud.google.com, *.crowdsource.google.com, *.datacompute.google.com, *.flash.android.com...

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://profiles.google.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://profiles.google.com/ returns 404 (no redirect to HTTPS).

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on profiles.google.com.

### 8. [INFO] HTTPS homepage returned HTTP 404 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://profiles.google.com/ responded 404 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://profiles.google.com/ final status: 404 (final URL https://profiles.google.com/).
- http://profiles.google.com/ initial status: 404.
- Certificate: Google Trust Services WR2, valid until 2026-12-03T19:21:52+00:00.
