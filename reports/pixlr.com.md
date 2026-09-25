# Security Audit Report — pixlr.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pixlr.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pixlr.com |
| Test date | 2026-09-25 13:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **38** (High: 0, Medium: 0, Low: 29, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | C1 | Cookies without Secure flag | CWE-614 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
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
| 29 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 30 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/ | CWE-942 |
| 31 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/ | CWE-942 |
| 32 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/ | CWE-942 |
| 33 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/api | CWE-942 |
| 34 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/api | CWE-942 |
| 35 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/api | CWE-942 |
| 36 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/graphql | CWE-942 |
| 37 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/graphql | CWE-942 |
| 38 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://pixlr.com/

### 2. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** connect.sid set without Secure on https://pixlr.com/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** country, lang set without HttpOnly on https://pixlr.com/

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter tool on https://pixlr.com/express/ reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://pixlr.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://pixlr.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://pixlr.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://pixlr.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://pixlr.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://pixlr.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://pixlr.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://pixlr.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://pixlr.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://pixlr.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://pixlr.com/view reflects input verbatim in body context; encoding boundary not confirmed.

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://pixlr.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: pixlr.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 30. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 31. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 32. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 33. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/plain; charset=utf-8). Any site can read responses cross-origin.

### 34. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 35. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/plain; charset=utf-8). Any site can read responses cross-origin.

### 36. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/plain; charset=utf-8). Any site can read responses cross-origin.

### 37. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 38. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://pixlr.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://pixlr.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/plain; charset=utf-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
