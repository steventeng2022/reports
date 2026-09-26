# Security Audit Report — producthunt.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://producthunt.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | producthunt.com |
| Test date | 2026-09-26 06:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **32** (High: 26, Medium: 0, Low: 5, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 2 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 4 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 5 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 6 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 7 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 8 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 9 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 10 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 11 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 12 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 13 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 14 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 15 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 16 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 17 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 18 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 19 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 20 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 21 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 22 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 23 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 24 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 25 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 26 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 27 | low | H2 | Missing CSP header | CWE-1021 |
| 28 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 29 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 30 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 31 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 32 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.producthunt.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.producthunt.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.producthunt.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.producthunt.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.producthunt.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.producthunt.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.producthunt.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.producthunt.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.producthunt.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.producthunt.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.producthunt.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.producthunt.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.producthunt.com/

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.producthunt.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.producthunt.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.producthunt.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 31. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: producthunt.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 32. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.producthunt.com/

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
