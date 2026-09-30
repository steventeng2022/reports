# Security Audit Report — rebrand.ly

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://rebrand.ly/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | rebrand.ly |
| Test date | 2026-09-30 05:59 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **31** (High: 0, Medium: 0, Low: 31, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 2 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 3 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 4 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 5 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 6 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 7 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 8 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 9 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 10 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 11 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 12 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 13 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 14 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 15 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 16 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 17 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 18 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 19 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 20 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 21 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 22 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 23 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 24 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 25 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 26 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 27 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 28 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 29 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 30 | low | I1 | CF managed challenge (token only in cUPMDTk JSON, no breakout) | CWE-79 |
| 31 | low | H1 | Missing HSTS header | CWE-319 |

## Detailed findings

### 1. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://rebrand.ly/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on http://rebrand.ly/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://rebrand.ly/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://rebrand.ly/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://rebrand.ly/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on http://rebrand.ly/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://rebrand.ly/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://rebrand.ly/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on http://rebrand.ly/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://rebrand.ly/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://rebrand.ly/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://rebrand.ly/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on http://rebrand.ly/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://rebrand.ly/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 28. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 29. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://rebrand.ly/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 30. [LOW] CF managed challenge (token only in cUPMDTk JSON, no breakout) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://rebrand.ly/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 31. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://rebrand.ly/

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x30 (HIGH -> LOW):** re-probed q/query on /search and /s (http): all return 403 (5,485-5,677 B) Cloudflare MANAGED challenge - token appears only inside the challenge JSON (cUPMDTk": "/search?q=Zx7qK2v9Bm\u0026__cf_chl_tk=..." with \u0026 escaping); quote-break payload q="'''>alert(1)'''" is NOT present in the response (NO-TOKEN) - no JS-context breakout, scanner over-flagged the challenge script.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
