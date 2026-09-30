# Security Audit Report — fortune.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fortune.com/ |
| Bug bounty program | Fortune |
| Listed scope domain | fortune.com |
| Test date | 2026-09-30 01:07 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **46** (High: 0, Medium: 1, Low: 36, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Public sponsored-content landing page from robots.txt (content discoverable, no hidden data) | CWE-538 |
| 2 | medium | I26 | WordPress user enumeration via REST API (wp-json/wp/v2/users) | CWE-200 |
| 3 | low | S1 | Subdomain on first-party CloudFront/AWS infrastructure (no dangling signature) | CWE-916 |
| 4 | low | S1 | Subdomain on first-party CloudFront/AWS infrastructure (no dangling signature) | CWE-916 |
| 5 | low | S1 | Subdomain on first-party CloudFront/AWS infrastructure (no dangling signature) | CWE-916 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
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
| 36 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 37 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 38 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 39 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 40 | info | H6 | Server technology disclosure | CWE-200 |
| 41 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/ | CWE-942 |
| 42 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/ | CWE-942 |
| 43 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/api | CWE-942 |
| 44 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/api | CWE-942 |
| 45 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/graphql | CWE-942 |
| 46 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Public sponsored-content landing page from robots.txt (no hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /sponsored/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [MEDIUM] WordPress user enumeration via REST API (wp-json/wp/v2/users) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://fortune.com/wp-json/wp/v2/users returned 200 (5424 bytes) with a matching signature.

### 3. [LOW] Subdomain on first-party CloudFront/AWS infrastructure - staging.fortune.com 503 awselb (no dangling signature) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain staging.fortune.com resolves to 54.239.180.30 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 4. [LOW] Subdomain on first-party CloudFront/AWS infrastructure - qa.fortune.com 401 nginx (no dangling signature) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain qa.fortune.com resolves to 65.9.180.15 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 5. [LOW] Subdomain on first-party CloudFront/AWS infrastructure - shop.fortune.com 200 Fortune Shop (no dangling signature) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain shop.fortune.com resolves to 13.249.182.2 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://fortune.com/

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://fortune.com/

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://fortune.com/

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://fortune.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://fortune.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://fortune.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://fortune.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://fortune.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://fortune.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://fortune.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://fortune.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://fortune.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://fortune.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://fortune.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://fortune.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 31. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 32. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 33. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 34. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 35. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fortune.com/view reflects input verbatim in body context; encoding boundary not confirmed.

### 36. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://fortune.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 37. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: fortune.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 38. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://fortune.com/

### 39. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://fortune.com/

### 40. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

### 41. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://fortune.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 42. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://fortune.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 43. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://fortune.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 44. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://fortune.com/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 45. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://fortune.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 46. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://fortune.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://fortune.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

## Active re-verification (2026-09-30, agent-aggressive)

- **I26 (KEPT MEDIUM):** /wp-json/wp/v2/users re-probed = 200 application/json (5,424 B) - a genuine WordPress REST user list (1 user exposed: id 12222172 / slug takarasmall, external contributor profile). Random path returns 308 (not a wildcard), so this is real user enumeration via WP REST.
- **S1 x3 (MEDIUM -> LOW):** staging.fortune.com re-probed = 503 (162 B, awselb/2.0 via CloudFront - Fortune's own AWS ELB origin with the staging app down); qa.fortune.com = 401 (172 B, nginx via CloudFront - live origin requiring auth); shop.fortune.com = 200 (273,089 B, "Fortune Shop", AmazonS3 via CloudFront - live first-party storefront). None show the 915 B CloudFront "request could not be satisfied" dangling signature, and all three sit on Fortune's own CloudFront/AWS infrastructure.
- **I22 (MEDIUM -> LOW):** /sponsored/ re-probed = 200 (226,132 B) public sponsored-content landing page (" | Fortune"), no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
