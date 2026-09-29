# Security Audit Report — box.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://box.net/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | box.net |
| Test date | 2026-09-29 22:23 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **31** (High: 28, Medium: 0, Low: 2, Info: 1)

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
| 29 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 30 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 31 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.box.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.box.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.box.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.box.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.box.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.box.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.box.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.box.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.box.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.box.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.box.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.box.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.box.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 28. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.box.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 29. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /core/ which returns 403, indicating a hidden/protected resource exists at that path.

### 30. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: box.net + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 31. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.box.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **I1 #1-28 (HIGH -> LOW):** re-probed the representative vectors (/search?q=, /s?q=, /redirect?url=, /out?url=, /go?url=, /r?url=, /share?url=) with both the scanner token Zx7qK2v9Bm and a quote/backslash breakout payload. Every request returns 403 (~5.7KB) Cloudflare MANAGED challenge (cf-mitigated: challenge, "Just a moment..." page). The token reflects only inside the challenge page JavaScript string cUPMDTk, where a double quote is percent-encoded (%22), a backslash is percent-encoded (%5C), and & becomes \u0026 - i.e. NOT raw inside the double-quoted JS string (verified: cUPMDTk:"/search?q=%22'%5C\u0026__cf_chl_tk=..." with no unescaped quote). This is the known CF cUPMDTk parity-safe false-positive family (same as npmjs.com), so all 28 findings are held LOW. box.net itself only 301-redirects to www.box.com.
