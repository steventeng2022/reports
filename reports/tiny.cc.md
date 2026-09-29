# Security Audit Report — tiny.cc

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://tiny.cc/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | tiny.cc |
| Test date | 2026-09-29 15:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 4, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://tiny.cc/ | CWE-942 |
| 3 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://tiny.cc/api | CWE-942 |
| 4 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://tiny.cc/graphql | CWE-942 |
| 5 | info | T2 | TLS certificate expiring within 35 days | CWE-295 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://tiny.cc/

### 2. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://tiny.cc/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://tiny.cc/ responds with Access-Control-Allow-Origin: * (Content-Type: text/plain charset=UTF-8). Any site can read responses cross-origin.

### 3. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://tiny.cc/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://tiny.cc/api responds with Access-Control-Allow-Origin: * (Content-Type: text/plain charset=UTF-8). Any site can read responses cross-origin.

### 4. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://tiny.cc/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://tiny.cc/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/plain charset=UTF-8). Any site can read responses cross-origin.

### 5. [INFO] TLS certificate expiring within 35 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for tiny.cc (CN=tiny.cc) valid_to Nov  3 01:21:43 2026 GMT.

### 6. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://tiny.cc/

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://tiny.cc/

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
