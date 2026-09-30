# Security Audit Report — maxcdn.bootstrapcdn.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://maxcdn.bootstrapcdn.com/ |
| Bug bounty program | BootstrapCDN |
| Listed scope domain | maxcdn.bootstrapcdn.com |
| Test date | 2026-09-30 05:31 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 3, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | Site served over plain HTTP without redirect to HTTPS | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/ | CWE-942 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/api | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/api | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/graphql | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/graphql | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Site served over plain HTTP without redirect to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://maxcdn.bootstrapcdn.com/ returned 200 directly (no 301/302 to HTTPS); content and cookies transit unencrypted.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://maxcdn.bootstrapcdn.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://maxcdn.bootstrapcdn.com/

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://maxcdn.bootstrapcdn.com/

### 5. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://maxcdn.bootstrapcdn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://maxcdn.bootstrapcdn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
