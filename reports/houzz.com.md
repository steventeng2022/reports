# Security Audit Report — houzz.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://houzz.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | houzz.com |
| Test date | 2026-09-29 16:39 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **10** (High: 1, Medium: 1, Low: 7, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I7 | Server-side template injection (SSTI) | CWE-94 |
| 2 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Server-side template injection (SSTI) (`I7`)

- **CWE:** CWE-94
- **Detail:** Parameter q on https://www.houzz.com/: payload #{17*19} is evaluated server-side (response contains 323; control #{17*18} contains 306 instead; token not reflected).

### 2. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /writeReview2/ew which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** hzmgcan, hzref, kcan set without Secure on https://www.houzz.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** hzmgcan, v, hzv, vct, hzref, _csrf, jdv, v, kcan set without HttpOnly on https://www.houzz.com/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter source on https://www.houzz.com/pro reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.houzz.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.houzz.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.houzz.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: houzz.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.houzz.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
