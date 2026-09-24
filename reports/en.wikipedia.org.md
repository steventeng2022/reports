# Security Audit Report — en.wikipedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://en.wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | en.wikipedia.org |
| Test date | 2026-09-24 12:05 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 12, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H4 | No clickjacking protection | CWE-1023 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://en.wikipedia.org/wiki/Main_Page

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** GeoIP, NetworkProbeLimit set without HttpOnly on https://en.wikipedia.org/wiki/Main_Page

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter modules on https://en.wikipedia.org/w/load.php reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://en.wikipedia.org/w/api.php reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://en.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://en.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://en.wikipedia.org/s reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://en.wikipedia.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://en.wikipedia.org/results reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://en.wikipedia.org/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://en.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: en.wikipedia.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://en.wikipedia.org/wiki/Main_Page

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
