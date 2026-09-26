# Security Audit Report — fastcompany.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fastcompany.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | fastcompany.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 3, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 11 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://fastcompany.com/ without HttpOnly: datadome. Readable by client-side script.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://fastcompany.com/. Clients may connect over plain HTTP on first visit.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://fastcompany.com/; browsers may MIME-sniff responses.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for fastcompany.com lists 21 name(s) besides the scope host: *.dev.inc.com, *.fast-co.net, *.fastcocreate.com, *.fastcodesign.com, *.fastcoexist.com, *.fastcolabs.com, *.fastcompany.com, *.fastcompany.net...

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://fastcompany.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://fastcompany.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://fastcompany.com/ lists 1657 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://fastcompany.com/ -> https://www.fastcompany.com/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://fastcompany.com/ exposes 2 unique Disallow path(s) (/, /rest) and 3 sitemap reference(s)

### 10. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on fastcompany.com.

### 11. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://fastcompany.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://fastcompany.com/ final status: 403 (final URL https://www.fastcompany.com/).
- http://fastcompany.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign Atlas R3 DV TLS CA 2026 Q2, valid until 2027-01-30T18:31:45+00:00.
