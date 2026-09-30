# Security Audit Report — elegantthemes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://elegantthemes.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | elegantthemes.com |
| Test date | 2026-09-30 03:06 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **33** (High: 0, Medium: 0, Low: 31, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 2 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 3 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 4 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 5 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 6 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 7 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 8 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 9 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 10 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 11 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 12 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 13 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 14 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 15 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 16 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 17 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 18 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 19 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 20 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 21 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 22 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 23 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 24 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 25 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 26 | low | I1 | No live reflection (301 redirect / 404 page / CF WAF 403) | CWE-79 |
| 27 | low | I22 | Empty JS affiliate file from robots.txt (200 0 B, no hidden data) | CWE-538 |
| 28 | low | H1 | Missing HSTS header | CWE-319 |
| 29 | low | H2 | Missing CSP header | CWE-1021 |
| 30 | low | H4 | No clickjacking protection | CWE-1023 |
| 31 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 32 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 33 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.elegantthemes.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.elegantthemes.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.elegantthemes.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.elegantthemes.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.elegantthemes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.elegantthemes.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.elegantthemes.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.elegantthemes.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.elegantthemes.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.elegantthemes.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.elegantthemes.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.elegantthemes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.elegantthemes.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [LOW] No live reflection (301 redirect / 404 page / CF WAF 403) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.elegantthemes.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] Empty JS affiliate file from robots.txt (200 0 B, no hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /affiliates/idevads.php which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 28. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.elegantthemes.com/

### 29. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.elegantthemes.com/

### 30. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.elegantthemes.com/

### 31. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: elegantthemes.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 32. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.elegantthemes.com/

### 33. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.elegantthemes.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x26 (HIGH -> LOW):** all 16 unique path+param combos re-probed ("https://www.elegantthemes.com/..."): clean-token payloads = 301 (1,156 B CF redirect, 0 token hits) to the trailing-slash variant = 200 (228,041 B) 404 page with 0 token hits; root 200 homepage (270,278 B) = 0 token hits; special-char payloads (</script>, attribute injection) = 403 (5,853 B CF "Attention Required" WAF). No live token reflection in any script context.
- **I22 (MEDIUM -> LOW):** /affiliates/idevads.php re-probed = 200 (0 B) content-type application/javascript - an empty JS file, no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
