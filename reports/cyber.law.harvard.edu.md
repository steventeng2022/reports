# Security Audit Report — cyber.law.harvard.edu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cyber.law.harvard.edu/ |
| Bug bounty program | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| Listed scope domain | cyber.law.harvard.edu |
| Test date | 2026-09-25 19:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 0, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | H2 | Short HSTS max-age | CWE-319 |
| 2 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 3 | info | H2c | HSTS not preloaded | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 7 | info | T0 | TLS handshake could not be completed | CWE-200 |
| 8 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=1000 (< 1 year): `max-age=1000`.

### 2. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=1000` does not cover subdomains.

### 3. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=1000` lacks the preload directive.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://cyber.law.harvard.edu/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://cyber.law.harvard.edu/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://cyber.law.harvard.edu (34941 bytes)

### 7. [INFO] TLS handshake could not be completed (`T0`)

- **CWE:** CWE-200
- **Detail:** No TLS version completed a handshake on cyber.law.harvard.edu:443 (versions: {'TLSv1.0': False, 'TLSv1.1': False, 'TLSv1.2': False, 'TLSv1.3': False}; errors: ['TLSv1.0: TimeoutError: timed out', 'TLSv1.1: [SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1010)']).

### 8. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://cyber.law.harvard.edu/ redirects to https://cyber.harvard.edu/.

## Reproduction notes

- Scanned 2026-09-25 19:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://cyber.law.harvard.edu/ final status: 200 (final URL https://cyber.harvard.edu/).
