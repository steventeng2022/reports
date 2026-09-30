# Security Audit Report — adweek.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://adweek.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | adweek.com |
| Test date | 2026-09-29 23:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 17, Info: 3)

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
| 11 | low | H1 | Missing HSTS header | CWE-319 |
| 12 | low | H2 | Missing CSP header | CWE-1021 |
| 13 | low | H4 | No clickjacking protection | CWE-1023 |
| 14 | low | C1 | Cookies without Secure flag | CWE-614 |
| 15 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 16 | low | I33 | WordPress user enumeration via ?author=1 | CWE-200 |
| 17 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 18 | info | T2 | TLS certificate expiring within 40 days | CWE-295 |
| 19 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 20 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.adweek.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.adweek.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.adweek.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.adweek.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.adweek.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.adweek.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.adweek.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.adweek.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.adweek.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected token in JavaScript context (challenge/sanitization boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.adweek.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.adweek.com/

### 12. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.adweek.com/

### 13. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.adweek.com/

### 14. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** blaize_session, blaize_tracking_id set without Secure on https://www.adweek.com/

### 15. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** blaize_session, blaize_tracking_id set without HttpOnly on https://www.adweek.com/

### 16. [LOW] WordPress user enumeration via ?author=1 (`I33`)

- **CWE:** CWE-200
- **Detail:** GET https://www.adweek.com/?author=1 returns 301 -> https://www.adweek.com/author/random/; author slug (username) disclosed. Combine with xmlrpc.php for brute force.

### 17. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: adweek.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 18. [INFO] TLS certificate expiring within 40 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.adweek.com (CN=www.adweek.com) valid_to Nov  8 15:05:42 2026 GMT.

### 19. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.adweek.com/

### 20. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.adweek.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x10 (HIGH -> LOW):** GET /s?q=PAYLOAD re-probed = 404 (179,958-179,996 B) article-not-found page; the plain token reflects twice, inside <script type="application/ld+json"> (mainEntityOfPage) and the StumbleUpon _stq.push tracking string, with the </script> sequence mangled to "script" (angle brackets stripped) so the script block cannot be closed; the attribute-injection and quote-string payloads return 0 token hits. No exploitable breakout -> LOW.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
