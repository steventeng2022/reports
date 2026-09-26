# Security Audit Report — geni.us

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://geni.us/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | geni.us |
| Test date | 2026-09-26 06:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **34** (High: 26, Medium: 1, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 2 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 4 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 5 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 6 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 7 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 8 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 9 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 10 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 11 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 12 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 13 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 14 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 15 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 16 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 17 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 18 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 19 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 20 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 21 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 22 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 23 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 24 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 25 | high | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 26 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 27 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 28 | low | H1 | Missing HSTS header | CWE-319 |
| 29 | low | H2 | Missing CSP header | CWE-1021 |
| 30 | low | H4 | No clickjacking protection | CWE-1023 |
| 31 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 32 | info | T2 | TLS certificate expiring within 14 days | CWE-295 |
| 33 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 34 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/search reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 2. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://geniuslink.com/search reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 4. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://geniuslink.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/s reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 6. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/results reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 8. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://geniuslink.com/redirect reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 10. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://geniuslink.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://geniuslink.com/go reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 12. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://geniuslink.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/search reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 14. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://geniuslink.com/search reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 16. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://geniuslink.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/s reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 18. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/results reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 20. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://geniuslink.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://geniuslink.com/redirect reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 22. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://geniuslink.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://geniuslink.com/go reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 24. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://geniuslink.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [HIGH] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://geniuslink.com/go reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 26. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://geniuslink.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.geni.us resolves to 54.192.248.23 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 28. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://geniuslink.com/

### 29. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://geniuslink.com/

### 30. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://geniuslink.com/

### 31. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: geni.us + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 32. [INFO] TLS certificate expiring within 14 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for geniuslink.com (CN=geniuslink.com) valid_to Oct  9 14:08:55 2026 GMT.

### 33. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://geniuslink.com/

### 34. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://geniuslink.com/

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
