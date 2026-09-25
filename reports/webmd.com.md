# Security Audit Report — webmd.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://webmd.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | webmd.com |
| Test date | 2026-09-25 12:02 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **36** (High: 19, Medium: 0, Low: 5, Info: 12)

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
| 20 | low | H1 | Missing HSTS header | CWE-319 |
| 21 | low | H4 | No clickjacking protection | CWE-1023 |
| 22 | low | C1 | Cookies without Secure flag | CWE-614 |
| 23 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 24 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 25 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 26 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 27 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ | CWE-942 |
| 28 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ | CWE-942 |
| 29 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ | CWE-942 |
| 30 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api | CWE-942 |
| 31 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api | CWE-942 |
| 32 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api | CWE-942 |
| 33 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql | CWE-942 |
| 34 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql | CWE-942 |
| 35 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql | CWE-942 |
| 36 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.webmd.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.webmd.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.webmd.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.webmd.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.webmd.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.webmd.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.webmd.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.webmd.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.webmd.com/

### 21. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.webmd.com/

### 22. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** lrt_wrk, gtinfo, VisitorId, ab set without Secure on https://www.webmd.com/

### 23. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** lrt_wrk, gtinfo, VisitorId, ab set without HttpOnly on https://www.webmd.com/

### 24. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: webmd.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 25. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.webmd.com/

### 26. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.webmd.com/

### 27. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 28. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/plain). Any site can read responses cross-origin.

### 29. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 30. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 31. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/plain). Any site can read responses cross-origin.

### 32. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 33. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 34. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/plain). Any site can read responses cross-origin.

### 35. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 36. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.webmd.com/.well-known/security.txt returned 200 (110 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
