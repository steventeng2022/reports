# Security Audit Report — gist.github.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gist.github.com/ |
| Bug bounty program | [GitHub](https://hackerone.com/github) |
| Listed scope domain | gist.github.com |
| Test date | 2026-09-25 02:55 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 0, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for gist.github.com lists 2 name(s) besides the scope host: *.github.com, github.com

### 2. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://gist.github.com/; browser features (camera, mic, geolocation) unrestricted.

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://gist.github.com/ -> https://gist.github.com/ (positive check).

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://gist.github.com/ exposes 73 unique Disallow path(s) (*/.git/, */tarball/, */zipball/, /, /*&author=*)

### 5. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on gist.github.com.

## Reproduction notes

- Scanned 2026-09-25 02:55 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://gist.github.com/ final status: 200 (final URL https://gist.github.com/starred).
- http://gist.github.com/ initial status: 301.
- Certificate: Sectigo Limited Sectigo Public Server Authentication CA DV E36, valid until 2026-11-27T23:59:59+00:00.
