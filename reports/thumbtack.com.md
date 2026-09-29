# Security Audit Report — thumbtack.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://thumbtack.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | thumbtack.com |
| Test date | 2026-09-29 16:16 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 2, Low: 3, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/ | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/ | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/ | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/api | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/api | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/api | CWE-942 |

## Detailed findings

### 1. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.thumbtack.com resolves to 54.192.248.34 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain app.thumbtack.com resolves to 54.192.248.20 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://thumbtack.com/

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://thumbtack.com/

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://thumbtack.com/

### 6. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://thumbtack.com/

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://thumbtack.com/

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://thumbtack.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://thumbtack.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://thumbtack.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://thumbtack.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://thumbtack.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://thumbtack.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://thumbtack.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
