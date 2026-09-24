# Security Audit Report — arstechnica.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://arstechnica.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | arstechnica.com |
| Test date | 2026-09-24 22:14 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 0, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | H2 | Short HSTS max-age | CWE-319 |
| 2 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 3 | info | H2c | HSTS not preloaded | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 8 | info | T0 | TLS handshake could not be completed | CWE-200 |

## Detailed findings

### 1. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=2592000 (< 1 year): `max-age=2592000`.

### 2. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=2592000` does not cover subdomains.

### 3. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=2592000` lacks the preload directive.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://arstechnica.com/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://arstechnica.com/ -> https://arstechnica.com:443/ (positive check).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://arstechnica.com/ exposes 33 unique Disallow path(s) (*/*comments-page=, */*comments=, */comments/, */toggle-*.json?, */trackback/) and 1 sitemap reference(s)

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on arstechnica.com.

### 8. [INFO] TLS handshake could not be completed (`T0`)

- **CWE:** CWE-200
- **Detail:** No TLS version completed a handshake on arstechnica.com:443 (versions: {'TLSv1.0': False, 'TLSv1.1': False, 'TLSv1.2': False, 'TLSv1.3': False}; errors: ['TLSv1.0: [SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1010)', 'TLSv1.1: [SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1010)']).

## Reproduction notes

- Scanned 2026-09-24 22:14 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://arstechnica.com/ final status: 200 (final URL https://arstechnica.com/).
- http://arstechnica.com/ initial status: 301.
