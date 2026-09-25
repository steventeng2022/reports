# Security Audit Report — googlewebmastercentral.blogspot.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://googlewebmastercentral.blogspot.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | googlewebmastercentral.blogspot.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 9 | info | X2 | HTTPS homepage returned HTTP 404 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://googlewebmastercentral.blogspot.com/. Clients may connect over plain HTTP on first visit.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for googlewebmastercentral.blogspot.com lists 139 name(s) besides the scope host: *.blogspot.ae, *.blogspot.al, *.blogspot.am, *.blogspot.ba, *.blogspot.be, *.blogspot.bg, *.blogspot.ca, *.blogspot.ch... (2 no longer resolve)

### 3. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `blogspot.vn` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `bp.blogspot.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://googlewebmastercentral.blogspot.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://googlewebmastercentral.blogspot.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://googlewebmastercentral.blogspot.com/ returns 404 (no redirect to HTTPS).

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on googlewebmastercentral.blogspot.com.

### 9. [INFO] HTTPS homepage returned HTTP 404 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://googlewebmastercentral.blogspot.com/ responded 404 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://googlewebmastercentral.blogspot.com/ final status: 404 (final URL https://googlewebmastercentral.blogspot.com/).
- http://googlewebmastercentral.blogspot.com/ initial status: 404.
- Certificate: Google Trust Services WE2, valid until 2026-12-03T19:23:10+00:00.
