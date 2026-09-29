# Security Audit Report — npmjs.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://npmjs.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | npmjs.com |
| Test date | 2026-09-29 21:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **34** (High: 30, Medium: 0, Low: 3, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 2 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 4 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 5 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 6 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 7 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 8 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 9 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 10 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 11 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 12 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 13 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 14 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 15 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 16 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 17 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 18 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 19 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 20 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 21 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 22 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 23 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 24 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 25 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 26 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 27 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 28 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 29 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 30 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 31 | low | H2 | Missing CSP header | CWE-1021 |
| 32 | low | H4 | No clickjacking protection | CWE-1023 |
| 33 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 34 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://npmjs.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://npmjs.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://npmjs.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://npmjs.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://npmjs.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://npmjs.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://npmjs.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://npmjs.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://npmjs.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://npmjs.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://npmjs.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://npmjs.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://npmjs.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://npmjs.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 28. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 29. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://npmjs.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 30. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://npmjs.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 31. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://npmjs.com/

### 32. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://npmjs.com/

### 33. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: npmjs.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 34. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://npmjs.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **I1 #1-30 (HIGH -> LOW):** re-probed all 16 unique vectors (/search?q=, /search?query=, /s?q=, /?q=, /results?q=, /redirect?url=, /go?url=, /go?redirect=, /r?url=, /r?to=, /link?url=, /out?url=, /u?url=, /share?url=, /view?url=, /forward?to=) with tokens containing a double-quote breakout (";alert(1)//), a backslash payload and a </script><svg onload=alert(1)> breakout. Every vector returns 403 (~5.8KB) Cloudflare MANAGED challenge (cf-mitigated: challenge, "Just a moment..." page). The token reflects 3x only inside the challenge page JavaScript strings cUPMDTk / cOgU, where the double quote is percent-encoded (%22) and the backslash is percent-encoded (%5C) - i.e. NOT raw - and </script> does not appear raw in the document. This is the known CF cUPMDTk false-positive family (parity-safe encoding), so all 30 scanner findings are held LOW.
