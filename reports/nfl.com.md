# Security Audit Report — nfl.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nfl.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nfl.com |
| Test date | 2026-09-30 03:06 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **17** (High: 0, Medium: 1, Low: 6, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | T3 | HTTP redirect does not go to HTTPS | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | T2 | TLS certificate expiring within 35 days | CWE-295 |
| 9 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/api | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/api | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/api | CWE-942 |
| 14 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/graphql | CWE-942 |
| 15 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/graphql | CWE-942 |
| 16 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/graphql | CWE-942 |
| 17 | info | I23 | XML sitemap exposes 1624 indexed URLs | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /_libraries/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] HTTP redirect does not go to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://nfl.com/ redirected to http://www.nfl.com/ (not an HTTPS URL).

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.nfl.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.nfl.com/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nfl.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nfl.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: nfl.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] TLS certificate expiring within 35 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.nfl.com (CN=nfl.com) valid_to Nov  3 16:38:03 2026 GMT.

### 9. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.nfl.com/

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.nfl.com/

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.nfl.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.nfl.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.nfl.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 14. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.nfl.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 15. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.nfl.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 16. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nfl.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.nfl.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 17. [INFO] XML sitemap exposes 1624 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.nfl.com/sitemap.xml returns a sitemap with 1624 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
