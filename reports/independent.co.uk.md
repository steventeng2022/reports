# Security Audit Report — independent.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://independent.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | independent.co.uk |
| Test date | 2026-09-29 23:07 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | C1 | Cookies without Secure flag | CWE-614 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/ | CWE-942 |
| 5 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/ | CWE-942 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/api | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/api | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/graphql | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/graphql | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.independent.co.uk/

### 2. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Locale, Locale set without Secure on https://www.independent.co.uk/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Locale, esi-permutive-id, Locale set without HttpOnly on https://www.independent.co.uk/

### 4. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 5. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.independent.co.uk/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.independent.co.uk/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
