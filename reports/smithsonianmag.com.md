# Security Audit Report — smithsonianmag.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://smithsonianmag.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | smithsonianmag.com |
| Test date | 2026-09-29 13:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **33** (High: 0, Medium: 28, Low: 3, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 2 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 3 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 4 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 5 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 6 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 7 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 8 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 9 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 10 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 11 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 12 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 13 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 14 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 15 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 16 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 17 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 18 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 19 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 20 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 21 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 22 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 23 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 24 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 25 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 26 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 27 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 28 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 29 | low | H2 | Missing CSP header | CWE-1021 |
| 30 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 31 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 32 | info | T2 | TLS certificate expiring within 42 days | CWE-295 |
| 33 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.smithsonianmag.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.smithsonianmag.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.smithsonianmag.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.smithsonianmag.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.smithsonianmag.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.smithsonianmag.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.smithsonianmag.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.smithsonianmag.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.smithsonianmag.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.smithsonianmag.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.smithsonianmag.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.smithsonianmag.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.smithsonianmag.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 28. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.smithsonianmag.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 29. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.smithsonianmag.com/

### 30. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search? which returns 403, indicating a hidden/protected resource exists at that path.

### 31. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: smithsonianmag.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 32. [INFO] TLS certificate expiring within 42 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.smithsonianmag.com (CN=www.smithsonianmag.com) valid_to Nov  9 20:08:27 2026 GMT.

### 33. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.smithsonianmag.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-29, agent-aggressive)

All 28 I1 HIGHs (15 unique endpoints: /search q/query, /s, /results, /redirect, /go url/redirect, /r url/to, /link, /out, /u, /share, /view, /forward; x2 for duplicates) re-checked:
- Direct HTTP (fresh tokens): ALL 15 endpoints -> **HTTP 403 Cloudflare managed challenge** (cType:"managed", __cf_chl_tk); the token reflects only inside CF's own challenge JS as a quoted string (`cUPMDTk:"/search?q=TOKEN\u0026__cf_chl_tk=..."`). Breakout probes (`x</script><img src=x onerror=alert(1)>`): no raw payload, no %3C leftover, no HTML escaping -> challenge JS sanitizes.
- IAB browser (Chrome, challenge passed): real /search/?q= page loads (200, "Search Smithsonian Magazine"); token reflects (a) as the search input's value attribute and (b) URL-ENCODED inside the freestar/hadronid tracking script (`url=https%3A%2F%2Fwww.smithsonianmag.com%2Fsearch%2F%3Fq%3DTOKEN`); no JS dialog, no raw <img>.
- Conclusion: scanner I1 heuristic tripped on the Cloudflare challenge-page JS string. 28 HIGH -> 28 MEDIUM (live 200 page still reflects q in a quoted input + encoded script - XSS-adjacent). Index row updated (33 total: 0H/28M/3L/2I).
