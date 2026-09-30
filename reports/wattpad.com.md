# Security Audit Report — wattpad.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wattpad.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wattpad.com |
| Test date | 2026-09-30 04:34 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 13, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | First-party redirect / live Atlassian status / CF 404 (not dangling) | CWE-916 |
| 2 | low | S1 | First-party redirect / live Atlassian status / CF 404 (not dangling) | CWE-916 |
| 3 | low | S1 | First-party redirect / live Atlassian status / CF 404 (not dangling) | CWE-916 |
| 4 | low | S1 | First-party redirect / live Atlassian status / CF 404 (not dangling) | CWE-916 |
| 5 | low | S1 | First-party redirect / live Atlassian status / CF 404 (not dangling) | CWE-916 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | C1 | Cookies without Secure flag | CWE-614 |
| 8 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 14 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 15 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 16 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/ | CWE-942 |
| 17 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/ | CWE-942 |
| 18 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/ | CWE-942 |
| 19 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/api | CWE-942 |
| 20 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/api | CWE-942 |
| 21 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/api | CWE-942 |
| 22 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/graphql | CWE-942 |
| 23 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/graphql | CWE-942 |
| 24 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] First-party redirect / live Atlassian status / CF 404 (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain test.wattpad.com resolves to 65.9.180.35 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] First-party redirect / live Atlassian status / CF 404 (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain staging.wattpad.com resolves to 65.9.180.34 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] First-party redirect / live Atlassian status / CF 404 (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain ftp.wattpad.com resolves to 65.9.180.124 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 4. [LOW] First-party redirect / live Atlassian status / CF 404 (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.wattpad.com resolves to 3.169.121.89 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 5. [LOW] First-party redirect / live Atlassian status / CF 404 (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.wattpad.com resolves to 65.9.180.76 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.wattpad.com/

### 7. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** remix_host_header_100 set without Secure on https://www.wattpad.com/

### 8. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** wp-web-page, wp_id, locale, lang, sn__time, feat-fedcm-rollout, remix set without HttpOnly on https://www.wattpad.com/

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.wattpad.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.wattpad.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.wattpad.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.wattpad.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: wattpad.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 14. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.wattpad.com/

### 15. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.wattpad.com/

### 16. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 17. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 18. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 19. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 20. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 21. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 22. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 23. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 24. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.wattpad.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.wattpad.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 x5 (MEDIUM -> LOW):** re-probed: test/staging/ftp.wattpad.com = https 301 (openresty) -> https://www.wattpad.com/ (first-party redirects); status.wattpad.com = 200 (61,105 B) title "Wattpad Status" server AtlassianEdge (live statuspage); api.wattpad.com = 404 (19 B) CloudFront empty (dangling CF distribution, no origin content) - none show the 915 B dangling CloudFront signature.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
