# Security Audit Report — edition.cnn.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://edition.cnn.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | edition.cnn.com |
| Test date | 2026-09-29 16:39 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 3, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/ | CWE-942 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/api | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/api | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/graphql | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/graphql | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://edition.cnn.com/

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** SecGpc, countryCode, stateCode, geoData, wbdFch set without HttpOnly on https://edition.cnn.com/

### 3. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: edition.cnn.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://edition.cnn.com/

### 5. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://edition.cnn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://edition.cnn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
