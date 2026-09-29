# Security Audit Report — git-scm.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://git-scm.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | git-scm.com |
| Test date | 2026-09-29 23:07 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/api | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/graphql | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/graphql | CWE-942 |
| 12 | info | I23 | XML sitemap exposes 3099 indexed URLs | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://git-scm.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://git-scm.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://git-scm.com/

### 4. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://git-scm.com/

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://git-scm.com/

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://git-scm.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://git-scm.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://git-scm.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://git-scm.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://git-scm.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://git-scm.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://git-scm.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 12. [INFO] XML sitemap exposes 3099 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://git-scm.com/sitemap.xml returns a sitemap with 3099 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
