# Security Audit Report — news.nationalgeographic.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://news.nationalgeographic.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | news.nationalgeographic.com |
| Test date | 2026-09-30 04:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **41** (High: 0, Medium: 1, Low: 35, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | C1 | Cookies without Secure flag | CWE-614 |
| 6 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
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
| 29 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 30 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 31 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 32 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 33 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 34 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 35 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 36 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 37 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 38 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 39 | info | H6 | Server technology disclosure | CWE-200 |
| 40 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nationalgeographic.com/graphql | CWE-942 |
| 41 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nationalgeographic.com/graphql | CWE-942 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /ads/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.nationalgeographic.com/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.nationalgeographic.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.nationalgeographic.com/

### 5. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** country, region, _dcf, SWID, userab_1 set without Secure on https://www.nationalgeographic.com/

### 6. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** country, region, _dcf, SWID, userab_1 set without HttpOnly on https://www.nationalgeographic.com/

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter gblftr on https://www.nationalgeographic.com/newsletters/signup reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nationalgeographic.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.nationalgeographic.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nationalgeographic.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nationalgeographic.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nationalgeographic.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.nationalgeographic.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.nationalgeographic.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nationalgeographic.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.nationalgeographic.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nationalgeographic.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nationalgeographic.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nationalgeographic.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.nationalgeographic.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.nationalgeographic.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 31. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 32. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 33. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 34. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.nationalgeographic.com/view reflects input verbatim in body context; encoding boundary not confirmed.

### 35. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.nationalgeographic.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 36. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: news.nationalgeographic.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 37. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.nationalgeographic.com/

### 38. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.nationalgeographic.com/

### 39. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

### 40. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nationalgeographic.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.nationalgeographic.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=iso-8859-1). Any site can read responses cross-origin.

### 41. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.nationalgeographic.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.nationalgeographic.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=iso-8859-1). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
