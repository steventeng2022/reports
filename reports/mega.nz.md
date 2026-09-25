# Security Audit Report — mega.nz

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mega.nz/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mega.nz |
| Test date | 2026-09-25 13:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 2 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/ | CWE-942 |
| 3 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/api | CWE-942 |
| 4 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/graphql | CWE-942 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/ | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/api | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/graphql | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** geoip set without HttpOnly on https://mega.nz/

### 2. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/ responds with Access-Control-Allow-Origin: * (Content-Type: application/json). Any site can read responses cross-origin.

### 3. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/api responds with Access-Control-Allow-Origin: * (Content-Type: application/json). Any site can read responses cross-origin.

### 4. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/graphql responds with Access-Control-Allow-Origin: * (Content-Type: application/json). Any site can read responses cross-origin.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://mega.nz/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://mega.nz/

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://mega.nz/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://mega.nz/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
