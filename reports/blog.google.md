# Security Audit Report — blog.google

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blog.google/ |
| Bug bounty program | Google |
| Listed scope domain | blog.google |
| Test date | 2026-09-24 22:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **34** (High: 0, Medium: 9, Low: 23, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 2 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 3 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 4 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 5 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 6 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 7 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 8 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 9 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
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
| 33 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 34 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/ with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 2. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/ with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 3. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/ with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 4. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/api with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 5. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/api with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 6. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/api with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 7. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/graphql with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 8. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://blog.google/graphql with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 9. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

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
- **Detail:** Requesting the origin with Host: blog.google + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 33. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://blog.google/

### 34. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://blog.google/

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
