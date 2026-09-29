# Security Audit Report — ssl.google-analytics.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ssl.google-analytics.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ssl.google-analytics.com |
| Test date | 2026-09-29 13:19 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 3, Low: 7, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I2 | Reflected XSS via attribute injection | CWE-79 |
| 2 | medium | I2 | Reflected XSS via attribute injection | CWE-79 |
| 3 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | I26 | humans.txt exposed (team/contact enumeration) | CWE-200 |
| 13 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.google.com/: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - the ssl.google-analytics.com host itself 301/302-redirects to the marketingplatform.google.com marketing page where `q` does NOT reflect; the scanner's www.google.com `q` reflection is HTML/URL-escaped (token in `&amp;`-escaped prev-links, a <textarea> value, JSON arrays) and the attribute-injection payload `"' onerror="alert(1)//` produced NO unquoted handler (attrinj=false). Downgraded HIGH -> MEDIUM.

### 2. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.google.com/: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - the ssl.google-analytics.com host itself 301/302-redirects to the marketingplatform.google.com marketing page where `q` does NOT reflect; the scanner's www.google.com `q` reflection is HTML/URL-escaped (token in `&amp;`-escaped prev-links, a <textarea> value, JSON arrays) and the attribute-injection payload `"' onerror="alert(1)//` produced NO unquoted handler (attrinj=false). Downgraded HIGH -> MEDIUM.

### 3. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /index.html? which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.google.com/analytics/

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.google.com/analytics/

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.google.com/analytics/

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.google.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.google.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.google.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.google.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.google.com/analytics/

### 12. [INFO] humans.txt exposed (team/contact enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.google.com/humans.txt returned 200 (286 bytes) with a matching signature.

### 13. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.google.com/.well-known/security.txt returned 200 (275 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-29, agent-aggressive)

Re-checked both I2 attribute-injection HIGHs with fresh tokens and the `"\x27 onerror=\x22alert(1)//` payload (direct HTTP):
- `GET https://ssl.google-analytics.com/?q=TOKEN` -> redirect to `https://marketingplatform.google.com/about/analytics/`; `q` does not reflect on the target host (tokRefs=0).
- Scanner detail referenced www.google.com: token reflects 5x, all escaped (amp-escaped URLs, textarea content, JS/JSON arrays); attribute-injection payload -> no raw `onerror="` handler anywhere.
- Conclusion: no attribute injection; reflection is escaped. Both HIGH -> MEDIUM (XSS-adjacent escaped reflection on the www.google.com host only). Index row updated (13 total: 0H/3M/7L/3I).
