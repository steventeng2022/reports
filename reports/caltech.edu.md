# Security Audit Report - caltech.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://caltech.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | caltech.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 4, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | C1 | __cf_bm cookie set without Secure flag | CWE-614 |
| 3 | info | S1 | www2.caltech.edu serves empty page via Caddy | CWE-916 |
| 4 | info | S1 | download.caltech.edu returns 403 (IIS) | CWE-916 |
| 5 | info | S1 | test.caltech.edu 403 behind Cloudflare | CWE-916 |
| 6 | low | S1 | assets.caltech.edu redirects to /login/ | CWE-916 |
| 7 | info | S1 | Unreachable subdomains (api / docs / portal / files / dl / mail / smtp) | CWE-916 |
| 8 | low | S1 | help.caltech.edu Web Help Desk | CWE-916 |

## Detailed findings

### 1. [LOW] Missing HSTS header (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.caltech.edu/.

### 2. [LOW] __cf_bm cookie set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** Cloudflare bot-management cookie __cf_bm set on the homepage without the Secure flag.

### 3. [INFO] www2.caltech.edu serves empty page via Caddy (S1)

- **CWE:** CWE-916
- **Detail:** www2.caltech.edu 200 (0 B, server Caddy) - secondary web host serving an empty body.

### 4. [INFO] download.caltech.edu returns 403 (IIS) (S1)

- **CWE:** CWE-916
- **Detail:** download.caltech.edu 403 (1804 B Microsoft-IIS/10.0).

### 5. [INFO] test.caltech.edu 403 behind Cloudflare (S1)

- **CWE:** CWE-916
- **Detail:** test.caltech.edu 403 (4548 B Cloudflare) - test subdomain live behind the CDN.

### 6. [LOW] assets.caltech.edu redirects to /login/ (S1)

- **CWE:** CWE-916
- **Detail:** assets.caltech.edu 302 to /login/ - asset path gated behind a login redirect.

### 7. [INFO] Unreachable subdomains (api / docs / portal / files / dl / mail / smtp) (S1)

- **CWE:** CWE-916
- **Detail:** api, docs, portal, files, dl ECONNRESET; mail, smtp ECONNREFUSED 131.215.239.38:80 from external vantage.

### 8. [LOW] help.caltech.edu Web Help Desk (S1)

- **CWE:** CWE-916
- **Detail:** help.caltech.edu 200 (1120 B) first-party help desk.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
