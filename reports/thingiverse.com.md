# Security Audit Report — thingiverse.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://thingiverse.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | thingiverse.com |
| Test date | 2026-09-30 07:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **40** (High: 0, Medium: 1, Low: 36, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/ | CWE-942 |
| 5 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/ | CWE-942 |
| 6 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/ | CWE-942 |
| 7 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/api | CWE-942 |
| 8 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/api | CWE-942 |
| 9 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/api | CWE-942 |
| 10 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/graphql | CWE-942 |
| 11 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/graphql | CWE-942 |
| 12 | low | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/graphql | CWE-942 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 15 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 16 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 17 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 18 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 19 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 20 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 21 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 22 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 23 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 24 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 25 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 26 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 27 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 28 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 29 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 30 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 31 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 32 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 33 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 34 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 35 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 36 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 37 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 38 | info | T2 | TLS certificate expiring within 33 days | CWE-295 |
| 39 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 40 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /messages/compose which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.thingiverse.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.thingiverse.com/

### 4. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 5. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 6. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 7. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 8. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 9. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 10. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 11. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 12. [LOW] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.thingiverse.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.thingiverse.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.thingiverse.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.thingiverse.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.thingiverse.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.thingiverse.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.thingiverse.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.thingiverse.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.thingiverse.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.thingiverse.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 31. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 32. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 33. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 34. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 35. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.thingiverse.com/view reflects input verbatim in body context; encoding boundary not confirmed.

### 36. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.thingiverse.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 37. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: thingiverse.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 38. [INFO] TLS certificate expiring within 33 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.thingiverse.com (CN=*.thingiverse.com) valid_to Nov  1 23:59:59 2026 GMT.

### 39. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.thingiverse.com/

### 40. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.thingiverse.com/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
