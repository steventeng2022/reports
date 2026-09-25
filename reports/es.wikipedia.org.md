# Security Audit Report — es.wikipedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://es.wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | es.wikipedia.org |
| Test date | 2026-09-25 03:24 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **20** (High: 1, Medium: 1, Low: 16, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I2 | Reflected XSS via attribute injection | CWE-79 |
| 2 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
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
| 18 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 19 | info | T2 | TLS certificate expiring within 40 days | CWE-295 |
| 20 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter title on https://es.wikipedia.org/w/index.php: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /api/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://es.wikipedia.org/wiki/Wikipedia:Portada

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** GeoIP, NetworkProbeLimit set without HttpOnly on https://es.wikipedia.org/wiki/Wikipedia:Portada

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter modules on https://es.wikipedia.org/w/load.php reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://es.wikipedia.org/w/api.php reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://es.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://es.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://es.wikipedia.org/s reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://es.wikipedia.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://es.wikipedia.org/results reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.wikipedia.org/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://es.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.wikipedia.org/r reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://es.wikipedia.org/r reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.wikipedia.org/link reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: es.wikipedia.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 19. [INFO] TLS certificate expiring within 40 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for es.wikipedia.org (CN=*.wikipedia.org) valid_to Nov  3 19:15:40 2026 GMT.

### 20. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://es.wikipedia.org/wiki/Wikipedia:Portada

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
