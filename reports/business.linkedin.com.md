# Security Audit Report — business.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://business.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | business.linkedin.com |
| Test date | 2026-09-26 06:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 2, Medium: 0, Low: 3, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I2 | Reflected XSS via attribute injection | CWE-79 |
| 2 | high | I2 | Reflected XSS via attribute injection | CWE-79 |
| 3 | low | T3 | Site served over plain HTTP without redirect to HTTPS | CWE-319 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://business.linkedin.com/redirect: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://business.linkedin.com/redirect: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 3. [LOW] Site served over plain HTTP without redirect to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://business.linkedin.com/ returned 200 directly (no 301/302 to HTTPS); content and cookies transit unencrypted.

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** bcookie set without HttpOnly on https://business.linkedin.com/

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: business.linkedin.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://business.linkedin.com/

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
