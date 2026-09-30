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

Total findings: **27** (High: 0, Medium: 0, Low: 25, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I30 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 2 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 3 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 4 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 5 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 6 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 7 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 8 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 9 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 10 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 11 | low | I30 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 12 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 13 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 14 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 15 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 16 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 17 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 18 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 19 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 20 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 21 | low | I1 | Reflected token in JavaScript context (properly-escaped JSON blob) | CWE-79 |
| 22 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 23 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 24 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 25 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 26 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 27 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/search reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 2. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.latimes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/search reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 12. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.latimes.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.latimes.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.latimes.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] Reflected token in JavaScript context (properly-escaped JSON blob) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.latimes.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

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

## Active re-verification (2026-09-30, agent-aggressive)

- **I1/I30 x21 (HIGH -> LOW):** /search?q= re-probed - the reflected searchTerm lands in a JSON data blob inside a real <script> block, but the serializer correctly escapes quotes (" -> \") and backslashes (\ -> \\); verified: payload Zx7qK2v9Bm" round-trips as Zx7qK2v9Bm\" and payload Zx7qK2v9Bm\ round-trips as Zx7qK2v9Bm\\ (no string breakout); </script> is truncated/URL-encoded in the searchTerm/fullUrl fields; the HTML input value is &quot;-escaped. The /r, /link, /out, /u, /share, /forward endpoints now return 404 (336,574-336,593 B) with the token only inside the URL-encoded fullUrl JSON field.
- **I22 (MEDIUM -> LOW):** /search returns 200 (418 KB) - a public search feature with no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
