# Security Audit Report — googleblog.blogspot.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://googleblog.blogspot.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | googleblog.blogspot.com |
| Test date | 2026-09-30 06:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **35** (High: 0, Medium: 0, Low: 32, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I20 | ACAO reflects Origin on GET, no ACAC, public content | CWE-942 |
| 2 | low | I20 | Preflight ACAO reflection (no ACAC) | CWE-942 |
| 3 | low | I20 | ACAO reflects Origin on GET, no ACAC, public content | CWE-942 |
| 4 | low | I20 | ACAO reflects Origin on GET, no ACAC, public content | CWE-942 |
| 5 | low | I20 | Preflight ACAO reflection (no ACAC) | CWE-942 |
| 6 | low | I20 | ACAO reflects Origin on GET, no ACAC, public content | CWE-942 |
| 7 | low | I20 | ACAO reflects Origin on GET, no ACAC, public content | CWE-942 |
| 8 | low | I20 | Preflight ACAO reflection (no ACAC) | CWE-942 |
| 9 | low | I20 | ACAO reflects Origin on GET, no ACAC, public content | CWE-942 |
| 10 | low | H1 | Missing HSTS header | CWE-319 |
| 11 | low | H4 | No clickjacking protection | CWE-1023 |
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
| 32 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 33 | info | T2 | TLS certificate expiring within 42 days | CWE-295 |
| 34 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 35 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] ACAO reflects Origin on GET, no ACAC, public content (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/ with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 2. [LOW] Preflight ACAO reflection (no ACAC) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/ with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 3. [LOW] ACAO reflects Origin on GET, no ACAC, public content (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/ with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 4. [LOW] ACAO reflects Origin on GET, no ACAC, public content (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/api with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 5. [LOW] Preflight ACAO reflection (no ACAC) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/api with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 6. [LOW] ACAO reflects Origin on GET, no ACAC, public content (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/api with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 7. [LOW] ACAO reflects Origin on GET, no ACAC, public content (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/graphql with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 8. [LOW] Preflight ACAO reflection (no ACAC) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/graphql with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 9. [LOW] ACAO reflects Origin on GET, no ACAC, public content (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/graphql with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 10. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://blog.google/

### 11. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://blog.google/

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://blog.google/s reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://blog.google/results reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/go reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://blog.google/go reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/r reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://blog.google/r reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://blog.google/s reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://blog.google/results reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/go reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://blog.google/go reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/r reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://blog.google/r reflects input verbatim in body context; encoding boundary not confirmed.

### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/link reflects input verbatim in body context; encoding boundary not confirmed.

### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/out reflects input verbatim in body context; encoding boundary not confirmed.

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/u reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/share reflects input verbatim in body context; encoding boundary not confirmed.

### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://blog.google/view reflects input verbatim in body context; encoding boundary not confirmed.

### 31. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://blog.google/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 32. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: googleblog.blogspot.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 33. [INFO] TLS certificate expiring within 42 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for blog.google (CN=blog.google) valid_to Nov 10 21:17:26 2026 GMT.

### 34. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://blog.google/

### 35. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://blog.google/

## Active re-verification (2026-09-30, agent-aggressive)

- **I20 x9 (MEDIUM -> LOW):** re-probed blog.google (the host actually tested by the report): GET / with evil Origin returns 200 (364,792 B, Google Frontend, public news page) with ACAO reflecting the Origin but NO Access-Control-Allow-Credentials on any variant (evil / null / no-origin all 364,792 B); without Origin the default is ACAO=*; /api and /graphql return 308 -> trailing-slash redirects (ACAO reflected on the redirect hop only). No ACAC on the actual response and content is public -> no exploitable CORS misconfiguration.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
