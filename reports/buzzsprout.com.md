# Security Audit Report — buzzsprout.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://buzzsprout.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | buzzsprout.com |
| Test date | 2026-09-25 03:24 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 2, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 3 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/ | CWE-942 |
| 4 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/ | CWE-942 |
| 5 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/ | CWE-942 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/api | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/api | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/api | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/graphql | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/graphql | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.buzzsprout.com/

### 2. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: buzzsprout.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 3. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 4. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 5. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.buzzsprout.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.buzzsprout.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
