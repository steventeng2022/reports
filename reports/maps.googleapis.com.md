# Security Audit Report — maps.googleapis.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://maps.googleapis.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | maps.googleapis.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 0, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 3 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 10 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for maps.googleapis.com lists 17 name(s) besides the scope host: *.clients.google.com, *.docs.google.com, *.drive.google.com, *.gdata.youtube.com, *.googleapis.com, *.photos.google.com, *.upload.google.com, *.upload.youtube.com... (5 no longer resolve)

### 2. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `bg-call-donation-alpha.goog` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 3. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `bg-call-donation-canary.goog` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `bg-call-donation-dev.goog` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://maps.googleapis.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://maps.googleapis.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://maps.googleapis.com/ -> https://developers.google.com/maps/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://maps.googleapis.com/ exposes 10 unique Disallow path(s) (/$rpc/google.internal.maps.gmpsdksbackend.v1.GmpSdksBackendService/, /$rpc/google.internal.maps.mapsjs.v1.MapsJsInternalService/, /%24rpc/google.internal.maps.gmpsdksbackend.v1.GmpSdksBackendService/, /%24rpc/google.internal.maps.mapsjs.v1.MapsJsInternalService/, /google.internal.maps.gmpsdksbackend.v1.GmpSdksBackendService/)

### 9. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on maps.googleapis.com.

### 10. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://maps.googleapis.com/ redirects to https://developers.google.com/maps/.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://maps.googleapis.com/ final status: 200 (final URL https://developers.google.com/maps/).
- http://maps.googleapis.com/ initial status: 302.
- Certificate: Google Trust Services WR2, valid until 2026-12-03T19:23:22+00:00.
