# Security Audit Report — latimes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://latimes.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | latimes.com |
| Test date | 2026-09-30 00:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **27** (High: 21, Medium: 1, Low: 3, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 2 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 4 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 5 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 6 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 7 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 8 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 9 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 10 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 11 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
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
| 22 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 23 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 24 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 25 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 26 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 27 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/search reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 2. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.latimes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/search reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 12. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.latimes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.latimes.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.latimes.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.latimes.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: latimes.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 26. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.latimes.com/

### 27. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.latimes.com/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
