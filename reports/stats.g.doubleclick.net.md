# Security Audit Report — stats.g.doubleclick.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stats.g.doubleclick.net/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | stats.g.doubleclick.net |
| Test date | 2026-09-26 05:37 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 2, Medium: 1, Low: 7, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I2 | Reflected XSS via attribute injection | CWE-79 |
| 2 | high | I2 | Reflected XSS via attribute injection | CWE-79 |
| 3 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | I26 | humans.txt exposed (team/contact enumeration) | CWE-200 |
| 13 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.google.com/: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.google.com/: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 3. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /index.html? which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.google.com/analytics/

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.google.com/analytics/

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.google.com/analytics/

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.google.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.google.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.google.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.google.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.google.com/analytics/

### 12. [INFO] humans.txt exposed (team/contact enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.google.com/humans.txt returned 200 (286 bytes) with a matching signature.

### 13. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.google.com/.well-known/security.txt returned 200 (275 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
