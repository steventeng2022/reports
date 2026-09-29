# Security Audit Report — ign.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ign.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ign.com |
| Test date | 2026-09-29 17:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 9, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 10 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/ | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/ | CWE-942 |
| 14 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/ | CWE-942 |
| 15 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/api | CWE-942 |
| 16 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/api | CWE-942 |
| 17 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/api | CWE-942 |
| 18 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/graphql | CWE-942 |
| 19 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/graphql | CWE-942 |
| 20 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.ign.com/

### 2. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.ign.com/

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** geoCC, geoRC set without Secure on https://www.ign.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** geoCC, geoRC set without HttpOnly on https://www.ign.com/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ign.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.ign.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ign.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.ign.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: ign.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 10. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.ign.com/

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.ign.com/

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 14. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 15. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 16. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 17. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 18. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 19. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 20. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.ign.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.ign.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
