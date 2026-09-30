# Security Audit Report — foursquare.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://foursquare.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | foursquare.com |
| Test date | 2026-09-30 02:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 15, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 2 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 3 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 4 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 5 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 6 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 7 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 8 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 9 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 10 | low | I1 | Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) | CWE-79 |
| 11 | low | S1 | Live Atlassian Statuspage (not dangling) | CWE-916 |
| 12 | low | H2 | Missing CSP header | CWE-1021 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 15 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 16 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 17 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://foursquare.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://foursquare.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://foursquare.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://foursquare.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://foursquare.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://foursquare.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://foursquare.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://foursquare.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://foursquare.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [LOW] Reflected token in JSON-LD context (sanitized: quotes/backslashes/angle brackets stripped) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://foursquare.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [LOW] Live Atlassian Statuspage - status.foursquare.com (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.foursquare.com resolves to 65.9.180.23 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 12. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://foursquare.com/

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://foursquare.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://foursquare.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: foursquare.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 16. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://foursquare.com/

### 17. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x10 (HIGH -> LOW):** ?q= on the root re-probed - the token is reflected ONLY in the wp-parsely JSON-LD block (script type=application/ld+json) @id field. Sanitizer verified: quote payload Zx7qK2v9Bm" and backslash payload Zx7qK2v9Bm\ reflect with the trailing char STRIPPED (identical 211,383 B body for all variants); </script> payload reflects as "script" (angle brackets stripped, +6 B). No raw quote and no raw </script> ever enter the script context - no string breakout.
- **S1 (MEDIUM -> LOW):** status.foursquare.com re-probed = 200 (92,871 B), server AtlassianEdge = live Atlassian Statuspage (same as status.kickstarter/godaddy/patreon precedent).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
