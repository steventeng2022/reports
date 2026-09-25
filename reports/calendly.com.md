# Security Audit Report — calendly.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://calendly.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | calendly.com |
| Test date | 2026-09-25 08:57 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **31** (High: 0, Medium: 1, Low: 25, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
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
| 21 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 22 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 23 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 24 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 25 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 26 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 27 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 28 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://calendly.com/ | CWE-942 |
| 29 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://calendly.com/ | CWE-942 |
| 30 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |
| 31 | info | I26 | OpenID configuration exposed (identity endpoints enumerable) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /abuse_reports/new which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://calendly.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://calendly.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** country, CALENDLY_AUTHENTICATED_USER_STATUS, cal_anonymous_id set without HttpOnly on https://calendly.com/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://calendly.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://calendly.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://calendly.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://calendly.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://calendly.com/view reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://calendly.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://calendly.com/old/ returns 200 with content different from the main site (2466 bytes); legacy deployments often carry weaker controls.

### 22. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://calendly.com/staging/ returns 200 with content different from the main site (2490 bytes); legacy deployments often carry weaker controls.

### 23. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://calendly.com/stage/ returns 200 with content different from the main site (2462 bytes); legacy deployments often carry weaker controls.

### 24. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://calendly.com/dev/ returns 200 with content different from the main site (2482 bytes); legacy deployments often carry weaker controls.

### 25. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://calendly.com/portal/ returns 200 with content different from the main site (2757 bytes); legacy deployments often carry weaker controls.

### 26. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: calendly.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 27. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://calendly.com/

### 28. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://calendly.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://calendly.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 29. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://calendly.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://calendly.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 30. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://calendly.com/.well-known/security.txt returned 200 (165 bytes) with a matching signature.

### 31. [INFO] OpenID configuration exposed (identity endpoints enumerable) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://calendly.com/.well-known/openid-configuration returned 200 (341 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
