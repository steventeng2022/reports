# Security Audit Report — loc.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://loc.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | loc.gov |
| Test date | 2026-09-30 04:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **31** (High: 0, Medium: 0, Low: 31, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 2 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 3 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 4 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 5 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 6 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 7 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 8 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 9 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 10 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 11 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 12 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 13 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 14 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 15 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 16 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 17 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 18 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 19 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 20 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 21 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 22 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 23 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 24 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 25 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 26 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 27 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 28 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 29 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 30 | low | I1 | Cloudflare managed-challenge reflection only (cUPMDTk, no app context) | CWE-79 |
| 31 | low | H1 | Missing HSTS header | CWE-319 |

## Detailed findings

### 1. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://loc.gov/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on http://loc.gov/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://loc.gov/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://loc.gov/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://loc.gov/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on http://loc.gov/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://loc.gov/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://loc.gov/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on http://loc.gov/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://loc.gov/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://loc.gov/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://loc.gov/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on http://loc.gov/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://loc.gov/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 28. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 29. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://loc.gov/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 30. [LOW] Cloudflare managed-challenge reflection only (cUPMDTk, no app context) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://loc.gov/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 31. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://loc.gov/

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x30 (HIGH -> LOW):** all 16 path/param combos (/ /results /s /search q+query, /go redirect+url, /forward to, /r to+url, /link /out /redirect /share /u /view url) re-probed on http+https = 403 (5,690-5,926 B) server Cloudflare cType:interactive managed challenge; token only inside the challenge-script JSON (cUPMDTk + __cf_chl_tk, 3 hits each); attr payload fully URL-encoded inside that JSON string (url%3D%22%27%20onerror%3D%22alert(1)%2F%2F); </script> payload produced no raw breakout (only CF own closing tag). The app was never reached = I1 rule over-flagged the Cloudflare challenge (stocktwits W35 / sciencemag W31 precedent).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
