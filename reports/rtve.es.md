# Security Audit Report — rtve.es

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://rtve.es/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | rtve.es |
| Test date | 2026-09-29 17:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **15** (High: 0, Medium: 7, Low: 5, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 2 | medium | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | medium | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 4 | medium | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 5 | medium | I30 | Reflected XSS in JavaScript context (alert payload round-trips) | CWE-79 |
| 6 | medium | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 7 | medium | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 8 | low | H1 | Missing HSTS header | CWE-319 |
| 9 | low | H2 | Missing CSP header | CWE-1021 |
| 10 | low | H4 | No clickjacking protection | CWE-1023 |
| 11 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 12 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 13 | info | T2 | TLS certificate expiring within 16 days | CWE-295 |
| 14 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 15 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter r on https://stories.rtve.es/noticias/newstory/stories/cc45201dc0bec403d0af reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 2. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter r on https://stories.rtve.es/noticias/newstory/stories/cc45201dc0bec403d0af reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [MEDIUM] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter r on https://stories.rtve.es/noticias/newstory/stories/34c04b5cbe3d86bfd8c7 reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 4. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter r on https://stories.rtve.es/noticias/newstory/stories/34c04b5cbe3d86bfd8c7 reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [MEDIUM] Reflected XSS in JavaScript context (alert payload round-trips) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter r on https://stories.rtve.es/noticias/newstory/stories/f00eb0ee2ef1184aa27b reflects ;alert(1)// unquoted inside a <script> block; JS executes on page load.

### 6. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter r on https://stories.rtve.es/noticias/newstory/stories/f00eb0ee2ef1184aa27b reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter r on https://stories.rtve.es/noticias/newstory/stories/d7c406fb35dac705d770 reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.rtve.es/

### 9. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.rtve.es/

### 10. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.rtve.es/

### 11. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /temporal/ which returns 403, indicating a hidden/protected resource exists at that path.

### 12. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: rtve.es + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 13. [INFO] TLS certificate expiring within 16 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.rtve.es (CN=*.rtve.es) valid_to Oct 15 09:49:22 2026 GMT.

### 14. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.rtve.es/

### 15. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.rtve.es/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)

- All 7 former-HIGH findings (1-7) target the `r` parameter on three `stories.rtve.es/noticias/newstory/stories/<id>` pages and claim raw (unquoted) reflection inside a `<script>` block.
- Live re-verification from the gate egress (Asia/Taipei) was BLOCKED: `stories.rtve.es` resolves to 51.75.166.69/.70/.72/.73 (Vodafone) and TCP-connect times out on both 80 and 443 (curl, node https and an in-app browser navigate all time out; all four IPs probed). The main site `www.rtve.es` (Fastly, 151.101.42.137) is healthy (200, 1,049,449 B) but does NOT reflect the `r` parameter (fresh token absent from the 1 MB homepage).
- The scanner's claim that the exact `**;alert(1)//**` payload round-trips unquoted inside `<script>` (I30) is the strongest reflection context seen in the I1 family, so these are held at MEDIUM (not LOW) pending re-verification from an EU/Spain vantage point. If the raw reflection is confirmed, findings 1-7 should be re-promoted to HIGH (CWE-79 reflected XSS).
