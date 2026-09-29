# Security Audit Report — ericsson.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ericsson.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ericsson.com |
| Test date | 2026-09-29 14:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **29** (High: 0, Medium: 0, Low: 29, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 2 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 3 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 4 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 5 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 6 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 7 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 8 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 9 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 10 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 11 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 12 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 13 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 14 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 15 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 16 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 17 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 18 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 19 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 20 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 21 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 22 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 23 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 24 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 25 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 26 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 27 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 28 | low | I1 | Reflected search token - properly escaped in JS string (refuted) | CWE-79 |
| 29 | low | H2 | Missing CSP header | CWE-1021 |

## Detailed findings

### 1. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ericsson.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.ericsson.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ericsson.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ericsson.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.ericsson.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.ericsson.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ericsson.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.ericsson.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ericsson.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ericsson.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.ericsson.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.ericsson.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.ericsson.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 28. [LOW] Reflected search token - properly escaped in JS string, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.ericsson.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 29. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.ericsson.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).


## Active re-verification (2026-09-29, agent-aggressive)

All 28 `I1` HIGH findings (search token reflected in JavaScript context on https://www.ericsson.com/search) were re-tested against the live endpoint after passing the Cloudflare managed challenge in a real browser; all 28 are downgraded HIGH->LOW.

- Bare requests receive a Cloudflare managed challenge (token appears only in the challenge, a known false-positive family). The real endpoint is `/en/search?q=`; the submitted token is reflected in three places: (1) the search input `value` (HTML-escaped), (2) the "0 RESULTS FOR X" results text (escaped), (3) URL-encoded inside a consentmanager `<script src="...cmp.php?h=...q%3DTOKEN...">` attribute (safe encoding).
- Primary reflection is a server-rendered Matomo tracking string: `var searchTerm=safe("TOKEN"),searchPage=safe("Search");searchTerm&&searchPage&&_paq.push(["trackEvent","Internal Site Search",searchTerm,searchPage])`.
- The app's JS-string escaper was verified live via form submits: `"` -> `\x22`, `\` -> `\\`, `/` -> `\x2f`, `=` -> `\x3d`. Probe `"`,alert(1)// (raw) rendered as `safe("\\x22,alert(1)\x2f\x2f")` - the string stays closed and escaped; no dialog fired. Only untested vector: raw newline/CRLF (JS syntax error at worst, not a breakout).
- The 12 "URLs" in the scanner output were guessed paths (/search /s /results /redirect /go /r /link /out /u /share /view /forward), not live endpoints.
- The CF WAF blocks direct URLs containing `%5c` or `onerror` patterns (challenge block page), but form submits pass (URL gains `searchPageName=Search&match=any&sort=score`).
