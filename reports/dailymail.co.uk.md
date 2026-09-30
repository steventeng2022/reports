# Security Audit Report — dailymail.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dailymail.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dailymail.co.uk |
| Test date | 2026-09-30 00:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 1, Low: 5, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | T3 | HTTP redirect does not go to HTTPS | CWE-319 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 7 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /api/infinite-list.html which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] HTTP redirect does not go to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://dailymail.co.uk/ redirected to http://www.dailymail.com/ (not an HTTPS URL).

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.dailymail.com/

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.dailymail.com/

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.dailymail.com/

### 6. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** gab set without HttpOnly on https://www.dailymail.com/

### 7. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.dailymail.com/

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.dailymail.com/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
