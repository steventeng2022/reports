# Security Audit Report — cancerresearchuk.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cancerresearchuk.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cancerresearchuk.org |
| Test date | 2026-09-25 16:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 2 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/ | CWE-942 |
| 5 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/ | CWE-942 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/graphql | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/graphql | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: cancerresearchuk.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 2. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.cancerresearchuk.org/

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.cancerresearchuk.org/

### 4. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.cancerresearchuk.org/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 5. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.cancerresearchuk.org/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.cancerresearchuk.org/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.cancerresearchuk.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.cancerresearchuk.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.cancerresearchuk.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.cancerresearchuk.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
