# Security Audit Report — science.sciencemag.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://science.sciencemag.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | science.sciencemag.org |
| Test date | 2026-09-29 23:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **32** (High: 0, Medium: 0, Low: 31, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 2 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 3 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 4 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 5 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 6 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 7 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 8 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 9 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 10 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 11 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 12 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 13 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 14 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 15 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 16 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 17 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 18 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 19 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 20 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 21 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 22 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 23 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 24 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 25 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 26 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 27 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 28 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 29 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 30 | low | I1 | Reflected token in JavaScript context (challenge/sanitization boundary) | CWE-79 |
| 31 | low | H1 | Missing HSTS header | CWE-319 |
| 32 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://science.sciencemag.org/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on http://science.sciencemag.org/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://science.sciencemag.org/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://science.sciencemag.org/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://science.sciencemag.org/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on http://science.sciencemag.org/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://science.sciencemag.org/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://science.sciencemag.org/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on http://science.sciencemag.org/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://science.sciencemag.org/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://science.sciencemag.org/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on http://science.sciencemag.org/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on http://science.sciencemag.org/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://science.sciencemag.org/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 28. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 29. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on http://science.sciencemag.org/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 30. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on http://science.sciencemag.org/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 31. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://science.sciencemag.org/

### 32. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET http://science.sciencemag.org/.well-known/security.txt returned 200 (65 bytes) with a matching signature.

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x30 (HIGH -> LOW):** GET /search?q=PAYLOAD re-probed = 403 (5,979 B) Cloudflare managed challenge (cType: managed); the token appears only URL-encoded inside the challenge-script fields cUPMDTk/fa (e.g. /search?q=Zx7qK2v9Bm%3C%2Fscript%3E...), never as raw </script>; the attribute-injection quote payload returns 0 token hits. Same CF cUPMDTk false-positive family as npmjs.com (W28) and box.net (W29) -> LOW.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
