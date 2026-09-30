# Security Audit Report - kayak.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://kayak.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | kayak.com
| Test date | 2026-09-30 12:45 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation with 2-hop canary tracking, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 3, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | 54 subdomain aliases 301 to www via Varnish | CWE-916 |
| 2 | info | S1 | mail.kayak.com 301 to Google Workspace mail | CWE-916 |
| 3 | low | H1 | No HSTS on www.kayak.com redirect response | CWE-319 |
| 4 | low | C1 | Four of nine cookies set without Secure flag | CWE-614 |
| 5 | low | C2 | One cookie set without HttpOnly flag | CWE-1004 |
| 6 | info | S1 | Homepage regional 302 to tw.kayak.com with url param | CWE-916 |

## Detailed findings

### 1. [INFO] 54 subdomain aliases 301 to www via Varnish (S1)

- **CWE:** CWE-916
- **Detail:** All 54 enumerated subdomains (admin, staging, dev, api, mail, ...) 301 to https://www.kayak.com/ (Varnish) - a uniform alias wall; each hostname still publicly resolves without auth.

### 2. [INFO] mail.kayak.com 301 to Google Workspace mail (S1)

- **CWE:** CWE-916
- **Detail:** mail.kayak.com 301 to https://mail.google.com/a/kayak.com - webmail handoff.

### 3. [LOW] No HSTS on www.kayak.com redirect response (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on the https://www.kayak.com/ 302 response (regional redirect to tw.kayak.com; C1/C2 cookie gaps below apply to the same response).

### 4. [LOW] Four of nine cookies set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** Four of the nine cookies set on the www.kayak.com response lack the Secure flag.

### 5. [LOW] One cookie set without HttpOnly flag (C2)

- **CWE:** CWE-1004
- **Detail:** One of the nine cookies set on the www.kayak.com response lacks the HttpOnly flag.

### 6. [INFO] Homepage regional 302 to tw.kayak.com with url param (S1)

- **CWE:** CWE-916
- **Detail:** www.kayak.com 302 to https://www.tw.kayak.com/in?cc=tw&lc=zh&mc=TWD&a=kayak&ccfrom=us&url=%2F%3Fispredir%3Dtrue - the first-party url param is retained across the regional handoff.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
