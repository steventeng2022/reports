# Security Audit Report — aclu.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aclu.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | aclu.org |
| Test date | 2026-09-30 07:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 2, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H4 | No clickjacking protection | CWE-1023 |
| 2 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 3 | info | T2 | TLS certificate expiring within 41 days | CWE-295 |
| 4 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/ | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/api | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/api | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/graphql | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/graphql | CWE-942 |
| 14 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.aclu.org/

### 2. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: aclu.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 3. [INFO] TLS certificate expiring within 41 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.aclu.org (CN=*.aclu.org) valid_to Nov  9 20:38:11 2026 GMT.

### 4. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.aclu.org/

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.aclu.org/

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 14. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.aclu.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.aclu.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
