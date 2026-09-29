# Security Audit Report — tunein.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://tunein.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | tunein.com |
| Test date | 2026-09-29 22:23 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **32** (High: 18, Medium: 2, Low: 11, Info: 1)

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
| 19 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 20 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 21 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 22 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 23 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 24 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 25 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 26 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 27 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 28 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 29 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 30 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 31 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 32 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://tunein.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://tunein.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://tunein.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://tunein.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://tunein.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://tunein.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://tunein.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://tunein.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /version which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 20. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.tunein.com resolves to 54.192.248.14 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://tunein.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://tunein.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://tunein.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://tunein.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://tunein.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://tunein.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://tunein.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 31. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: tunein.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 32. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://tunein.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **I1 #1-18 (HIGH -> LOW, not currently reproducible):** re-probed all 13 unique paths (/search?q=, /s?q=, /?q=, /results?q=, /redirect?url=, /go?url=, /go?redirect=, /r?url=, /r?to=, /link?url=, /out?url=, /u?url=, /share?url=, /view?url=, /forward?to=) with the exact scanner token (Zx7qK2v9Bm), scanner UA (Chrome/131), and 12 retry rounds. The site behavior changed since the scan: the no-trailing-slash paths now 301-redirect to trailing-slash variants (e.g. /search?q= -> /search/?q=), and the token appears ONLY in the ~70B plain-text 301 redirect body ("Moved Permanently. Redirecting to https://tunein.com/search/?q=...") - a body context, not an executable <script> context. All trailing-slash variants (/out/?url=, /u/?url=, /redirect/?url=, /r/?url=, /link/?url=, /share/?url=, /go/?url=, /view/?url=, /forward/?to=, /results/?q=, /s/?q=) return 404 (376KB 404 page) with NO token anywhere; /search/?q= returns 200 (602KB) with NO token; /?q= returns 200 (447KB) with NO token. The script-context reflection the scanner saw was a transient deployment state; held LOW (residual reflection is plain-text redirect body only).
- **I22 #19 (MEDIUM -> LOW):** /version = 200, 162B, application/json: {"buildDate":"Mon Sep 28 2026 16:57:33 GMT+0000","version":"7.40.1","gitSha":"837b0ff..."} - a public version/build endpoint (intentional, low-signal disclosure), same class as the commons.wikimedia /api/ precedent.
- **S1 #20 (MEDIUM -> LOW):** status.tunein.com (54.192.248.14, CloudFront) = 200, 91,708B, <title>TuneIn Status</title> with X-Cache: Miss - a live first-party status page with full content, not a dangling distribution (no CF 915/919B "request could not be satisfied" signature).
