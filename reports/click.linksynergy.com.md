# Security Audit Report — click.linksynergy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://click.linksynergy.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | click.linksynergy.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 9 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://click.linksynergy.com/. Clients may connect over plain HTTP on first visit.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for click.linksynergy.com lists 2 name(s) besides the scope host: *.linksynergy.com, linksynergy.com (1 no longer resolve)

### 3. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `linksynergy.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://click.linksynergy.com/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://click.linksynergy.com/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://click.linksynergy.com/ -> https://click.linksynergy.com/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://click.linksynergy.com/ exposes 1 unique Disallow path(s) (/)

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on click.linksynergy.com.

### 9. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://click.linksynergy.com/ redirects to https://rakutenadvertising.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://click.linksynergy.com/ final status: 200 (final URL https://rakutenadvertising.com).
- http://click.linksynergy.com/ initial status: 301.
- Certificate: ZeroSSL ZeroSSL RSA Domain Secure Site CA, valid until 2027-03-12T23:59:59+00:00.
