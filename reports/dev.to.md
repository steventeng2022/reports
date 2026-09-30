# Security Audit Report — dev.to

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dev.to/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dev.to |
| Test date | 2026-09-30 04:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 8, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Public CSRF-token JSON from robots.txt (low sensitivity) | CWE-538 |
| 2 | low | S1 | Live Atlassian Statuspage (not dangling) | CWE-916 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/ | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/ | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/ | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/api | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/api | CWE-942 |
| 14 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/api | CWE-942 |
| 15 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/graphql | CWE-942 |
| 16 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/graphql | CWE-942 |
| 17 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Public CSRF-token JSON from robots.txt (low sensitivity) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /async_info/base_data which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Live Atlassian Statuspage (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.dev.to resolves to 65.9.180.27 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter billboard on https://dev.to/report-abuse reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://dev.to/search reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://dev.to/ reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://dev.to/search reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://dev.to/ reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: dev.to + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 14. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 15. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

### 16. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 17. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://dev.to/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://dev.to/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=UTF-8). Any site can read responses cross-origin.

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 (MEDIUM -> LOW):** status.dev.to re-probed = https 200 (85,925 B) title "DEV Status" server AtlassianEdge = live Atlassian Statuspage (http 301 -> https) - first-party live infra, not dangling.
- **I22 (MEDIUM -> LOW):** /async_info/base_data re-probed = 200 (144 B) application/json "{"broadcast":null,"param":"authenticity_token","token":"..."}" (Heroku) - public CSRF-token/broadcast config, low sensitivity.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
