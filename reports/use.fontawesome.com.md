# Security Audit Report — use.fontawesome.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://use.fontawesome.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | use.fontawesome.com |
| Test date | 2026-09-30 06:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 3, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/api | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/graphql | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://use.fontawesome.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on http://use.fontawesome.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on http://use.fontawesome.com/

### 4. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on http://use.fontawesome.com/

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on http://use.fontawesome.com/

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://use.fontawesome.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://use.fontawesome.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://use.fontawesome.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://use.fontawesome.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://use.fontawesome.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://use.fontawesome.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://use.fontawesome.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
