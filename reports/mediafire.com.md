# Security Audit Report — mediafire.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mediafire.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mediafire.com |
| Test date | 2026-09-29 13:19 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 3, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies without Secure flag | CWE-614 |
| 2 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 3 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 4 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/ | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/api | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/api | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/graphql | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/graphql | CWE-942 |
| 14 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** ukey set without Secure on https://www.mediafire.com/

### 2. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.mediafire.com/dev/ returns 200 with content different from the main site (19882 bytes); legacy deployments often carry weaker controls.

### 3. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: mediafire.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 4. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.mediafire.com/

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.mediafire.com/

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 14. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.mediafire.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.mediafire.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
