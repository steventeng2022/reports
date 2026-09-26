# Security Audit Report — dw.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dw.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dw.com |
| Test date | 2026-09-26 09:29 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 1, Low: 6, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | C1 | Cookies without Secure flag | CWE-614 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/graphql | CWE-942 |
| 5 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/graphql | CWE-942 |
| 6 | low | I11 | GraphQL introspection enabled on /graphql | CWE-200 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/ | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/ | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/ | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/graphql | CWE-942 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** ab_test_user set without Secure on https://www.dw.com/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** ab_test_user set without HttpOnly on https://www.dw.com/

### 4. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.dw.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: application/json; charset=utf-8). Any site can read responses cross-origin.

### 5. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.dw.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: application/json; charset=utf-8). Any site can read responses cross-origin.

### 6. [LOW] GraphQL introspection enabled on /graphql (`I11`)

- **CWE:** CWE-200
- **Detail:** POST https://www.dw.com/graphql with {__schema{types{name}}} returns the full type map.

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: dw.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.dw.com/

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.dw.com/

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.dw.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.dw.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.dw.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.dw.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.dw.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
