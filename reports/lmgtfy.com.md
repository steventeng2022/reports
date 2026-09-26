# Security Audit Report — lmgtfy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lmgtfy.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | lmgtfy.com |
| Test date | 2026-09-26 06:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 4 | info | T2 | TLS certificate expiring within 38 days | CWE-295 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/ | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/ | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/api | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/api | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/api | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/graphql | CWE-942 |
| 14 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/graphql | CWE-942 |
| 15 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://lmgtfy.com/

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** lmgtfy.nav_menu, lmgtfy.active_subscription, creator set without HttpOnly on https://lmgtfy.com/

### 3. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://lmgtfy.com/old/ returns 200 with content different from the main site (22898 bytes); legacy deployments often carry weaker controls.

### 4. [INFO] TLS certificate expiring within 38 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for lmgtfy.com (CN=*.lmgtfy.com) valid_to Nov  2 07:07:07 2026 GMT.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://lmgtfy.com/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://lmgtfy.com/

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 14. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 15. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://lmgtfy.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://lmgtfy.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
