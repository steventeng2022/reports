# Security Audit Report — slate.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://slate.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | slate.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | info | H2c | HSTS not preloaded | CWE-319 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://slate.com/ without HttpOnly: AB, slate-uuid. Readable by client-side script.

### 2. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://slate.com/ -> https://slate.com/ (positive check).

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://slate.com/ exposes 9 unique Disallow path(s) (/, /_, /comments/, /css, /fonts) and 1 sitemap reference(s)

### 5. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on slate.com.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://slate.com/ final status: 200 (final URL https://slate.com/).
- http://slate.com/ initial status: 301.
- Certificate: Let's Encrypt YR1, valid until 2026-12-14T20:03:08+00:00.
