# Security Audit Report — journals.sagepub.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://journals.sagepub.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | journals.sagepub.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 0, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | H2 | Short HSTS max-age | CWE-319 |
| 2 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 3 | info | H2c | HSTS not preloaded | CWE-319 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 7 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

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

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://journals.sagepub.com/ -> https://journals.sagepub.com/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://journals.sagepub.com/ exposes 19 unique Disallow path(s) (/, /action, /author/, /authored-by/, /doi/metrics/) and 1 sitemap reference(s)

### 6. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://journals.sagepub.com (65 bytes); contact: mailto:security@wiley.com

### 7. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://journals.sagepub.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://journals.sagepub.com/ final status: 403 (final URL https://journals.sagepub.com/).
- http://journals.sagepub.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-02T05:47:45+00:00.
