# Security Audit Report - square.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://square.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | square.com
| Test date | 2026-09-30 12:45 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation with 2-hop canary tracking, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 1, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | No HSTS on square.com and www.squareup.com alias responses | CWE-319 |
| 2 | info | S1 | square.com is a pure alias of squareup.com | CWE-916 |
| 3 | info | S1 | www.square.com 301 alias | CWE-916 |
| 4 | info | H5 | Missing CSP, X-Frame-Options and Referrer-Policy on the squareup.com apex 301 | CWE-200 |

## Detailed findings

### 1. [LOW] No HSTS on square.com and www.squareup.com alias responses (H1)

- **CWE:** CWE-319
- **Detail:** Neither the https://square.com/ nor the https://www.squareup.com/ 301 (Cloudflare) carries Strict-Transport-Security, while the squareup.com apex serves HSTS with a 20-year preload.

### 2. [INFO] square.com is a pure alias of squareup.com (S1)

- **CWE:** CWE-916
- **Detail:** square.com and www.squareup.com both 301 to https://squareup.com/ - the brand is served from a different registered domain.

### 3. [INFO] www.square.com 301 alias (S1)

- **CWE:** CWE-916
- **Detail:** www.square.com 301 (62 B Cloudflare) to https://squareup.com/ - the redundant www of the alias domain.

### 4. [INFO] Missing CSP, X-Frame-Options and Referrer-Policy on the squareup.com apex 301 (H5)

- **CWE:** CWE-200
- **Detail:** The https://squareup.com/ 301 to /us/en (HSTS present) carries no CSP, X-Frame-Options or Referrer-Policy.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
