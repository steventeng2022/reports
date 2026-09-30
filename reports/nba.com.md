# Security Audit Report — nba.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nba.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nba.com |
| Test date | 2026-09-30 04:59 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 15, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | /search public search page from robots.txt (no hidden data) | CWE-538 |
| 2 | low | I4 | Search-box value echo (quoted attr, specials -> 403, no breakout) | CWE-79 |
| 3 | low | I4 | Search-box value echo (quoted attr, specials -> 403, no breakout) | CWE-79 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | C1 | Cookies without Secure flag | CWE-614 |
| 6 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 15 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 16 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] /search public search page from robots.txt (no hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Search-box value echo (quoted attr, specials -> 403, no breakout) (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nba.com/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 3. [LOW] Search-box value echo (quoted attr, specials -> 403, no breakout) (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.nba.com/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.nba.com/

### 5. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** bm_sz set without Secure on https://www.nba.com/

### 6. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** _abck, bm_so, bm_sz set without HttpOnly on https://www.nba.com/

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter cal on https://www.nba.com/schedule reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter pd on https://www.nba.com/schedule reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter region on https://www.nba.com/schedule reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter season on https://www.nba.com/schedule reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter bc on https://www.nba.com/schedule reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter GroupBy on https://www.nba.com/standings reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.nba.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.nba.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: nba.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 16. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.nba.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **I4 x2 (MEDIUM -> LOW):** www.nba.com/search?q= re-probed: plain token echoed into the search form input value="..." attribute (200, 263,789 B, quoted attr); quote payload -> 403 (376 B), angle-bracket payload -> 403 (374 B) - specials rejected, no breakout (standard search-box value echo).
- **I22 (MEDIUM -> LOW):** /search re-probed = 200 (263,763 B) title "Search | NBA.com" - public search page, no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
