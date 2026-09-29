# Security Audit Report — cnn.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cnn.com/ |
| Bug bounty program | CNN |
| Listed scope domain | cnn.com |
| Test date | 2026-09-29 20:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 5, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | C1 | Cookies without Secure flag | CWE-614 |
| 5 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/ | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/ | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/ | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/api | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/api | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/api | CWE-942 |
| 14 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/graphql | CWE-942 |
| 15 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/graphql | CWE-942 |
| 16 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://cnn.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on http://cnn.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on http://cnn.com/

### 4. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** countryCode, stateCode, geoData, FastAB set without Secure on http://cnn.com/

### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** countryCode, stateCode, geoData set without HttpOnly on http://cnn.com/

### 6. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on http://cnn.com/

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on http://cnn.com/

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 14. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 15. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 16. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on http://cnn.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET http://cnn.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
