# Security Audit Report — patreon.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://patreon.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | patreon.com |
| Test date | 2026-09-29 23:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **21** (High: 0, Medium: 2, Low: 15, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
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
| 17 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 18 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.patreon.com/ | CWE-942 |
| 19 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.patreon.com/ | CWE-942 |
| 20 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.patreon.com/ | CWE-942 |
| 21 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain mail.patreon.com resolves to 54.192.248.25 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 403

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.patreon.com resolves to 54.192.248.89 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.patreon.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.patreon.com/

### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** patreon_device_id, patreon_device_id, patreon_location_country_code, patreon_locale_code set without HttpOnly on https://www.patreon.com/

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter view on https://www.patreon.com/collection/700928 reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.patreon.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.patreon.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.patreon.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.patreon.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.patreon.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.patreon.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.patreon.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.patreon.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.patreon.com/view reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.patreon.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: patreon.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 18. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.patreon.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.patreon.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 19. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.patreon.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.patreon.com/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 20. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.patreon.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.patreon.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 21. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.patreon.com/.well-known/security.txt returned 200 (198 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
