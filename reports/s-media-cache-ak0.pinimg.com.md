# Security Audit Report — s-media-cache-ak0.pinimg.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://s-media-cache-ak0.pinimg.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | s-media-cache-ak0.pinimg.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 4 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 10 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |
| 11 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://s-media-cache-ak0.pinimg.com/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://s-media-cache-ak0.pinimg.com/; no defense-in-depth against XSS/content injection.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://s-media-cache-ak0.pinimg.com/; browsers may MIME-sniff responses.

### 4. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://s-media-cache-ak0.pinimg.com/; page may be rendered in a foreign frame.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for s-media-cache-ak0.pinimg.com lists 96 name(s) besides the scope host: *.pinimg.com, *.pinterest.at, *.pinterest.be, *.pinterest.ca, *.pinterest.ch, *.pinterest.cl, *.pinterest.co, *.pinterest.co.at...

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://s-media-cache-ak0.pinimg.com/; full URL (incl. query strings) is sent as referrer by default.

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://s-media-cache-ak0.pinimg.com/; browser features (camera, mic, geolocation) unrestricted.

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://s-media-cache-ak0.pinimg.com/ exposes 2 unique Disallow path(s) (/, /*nii=t)

### 9. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on s-media-cache-ak0.pinimg.com.

### 10. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://s-media-cache-ak0.pinimg.com/ responded 403 (passive check only; no further probing).

### 11. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://s-media-cache-ak0.pinimg.com/ redirects to https://i.pinimg.com/.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://s-media-cache-ak0.pinimg.com/ final status: 403 (final URL https://i.pinimg.com/).
- http://s-media-cache-ak0.pinimg.com/ initial status: 301.
- Certificate: DigiCert Inc DigiCert Global G2 TLS RSA SHA256 2020 CA1, valid until 2027-02-26T23:59:59+00:00.
