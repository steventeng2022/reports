# Security Audit Report — npr.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://npr.org/ |
| Bug bounty program | NPR |
| Listed scope domain | npr.org |
| Test date | 2026-09-30 06:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 8, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.npr.org/ | CWE-942 |
| 6 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.npr.org/ | CWE-942 |
| 7 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.npr.org/graphql | CWE-942 |
| 8 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.npr.org/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.npr.org/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.npr.org/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** bm_so set without HttpOnly on https://www.npr.org/

### 5. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.npr.org/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.npr.org/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 6. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.npr.org/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.npr.org/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 7. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.npr.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.npr.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 8. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: npr.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
