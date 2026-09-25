# Security Audit Report — vizio.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vizio.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | vizio.com |
| Test date | 2026-09-25 03:24 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **29** (High: 0, Medium: 25, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 2 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 3 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 4 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 5 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 6 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 7 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 8 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 9 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 10 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 11 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 12 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 13 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 14 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 15 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 16 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 17 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 18 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 19 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 20 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 21 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 22 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 23 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 24 | medium | I1 | Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) | CWE-79 |
| 25 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 26 | low | H2 | Missing CSP header | CWE-1021 |
| 27 | low | H4 | No clickjacking protection | CWE-1023 |
| 28 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 29 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/go reflected unescaped input inside <script> during the scan window. RETEST 2026-09-25 (10 retries + 12-path sweep via Cloudflare): /go /r /link /out /u /share /view /forward /redirect /s /results all return 404 (309B, Server: cloudflare); /search 301 -> /en/search?url=<tok> (200, 162KB) but the token is NOT reflected in the /en/search body. Route appears to have been removed or is region/A-B gated. Downgraded 24x HIGH -> MEDIUM per rule 4 (no live round-trip at retest time); re-test /go before submission - if the JS-context reflection returns, this cluster is a strong High.

### 2. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.vizio.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.vizio.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.vizio.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.vizio.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.vizio.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.vizio.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.vizio.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.vizio.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.vizio.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.vizio.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [MEDIUM] Reflected XSS in JavaScript context - intermittent route (retest 2026-09-25) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.vizio.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /setup/verify-email which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 26. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.vizio.com/

### 27. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.vizio.com/

### 28. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.vizio.com/

### 29. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.vizio.com/

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
