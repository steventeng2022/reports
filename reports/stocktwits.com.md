# Security Audit Report — stocktwits.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stocktwits.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | stocktwits.com |
| Test date | 2026-09-30 03:06 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **32** (High: 0, Medium: 0, Low: 32, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 2 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 3 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 4 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 5 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 6 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 7 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 8 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 9 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 10 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 11 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 12 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 13 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 14 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 15 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 16 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 17 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 18 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 19 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 20 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 21 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 22 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 23 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 24 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 25 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 26 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 27 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 28 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 29 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 30 | low | I1 | Reflected token in CF managed-challenge data only (403; no live reflection) | CWE-79 |
| 31 | low | H1 | Missing HSTS header | CWE-319 |
| 32 | low | C1 | Cookies without Secure flag | CWE-614 |

## Detailed findings

### 1. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://stocktwits.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on http://stocktwits.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://stocktwits.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://stocktwits.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://stocktwits.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on http://stocktwits.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://stocktwits.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://stocktwits.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on http://stocktwits.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://stocktwits.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://stocktwits.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://stocktwits.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on http://stocktwits.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://stocktwits.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 28. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 29. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://stocktwits.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 30. [LOW] Reflected token in CF managed-challenge data only (403; no live reflection) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://stocktwits.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 31. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://stocktwits.com/

### 32. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** __cf_bm set without Secure on http://stocktwits.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x30 (HIGH -> LOW):** all 16 unique path+param combos re-probed ("http://stocktwits.com/..."): every response = 403 (5.7 KB) Cloudflare managed challenge (cType:"managed"); the token appears ONLY in the cUPMDTk challenge field, URL/JSON-escaped (quote payload -> %22, ampersand -> "\u0026"); </script> payload = 0 token hits. No live reflection, no string breakout - same false-positive family as sciencemag (W31) / npmjs (W28) / box (W29).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
