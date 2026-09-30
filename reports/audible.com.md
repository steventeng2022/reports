# Security Audit Report — audible.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://audible.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | audible.com |
| Test date | 2026-09-30 07:27 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **16** (High: 0, Medium: 1, Low: 14, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | C1 | Cookies without Secure flag | CWE-614 |
| 5 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
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

### 1. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.audible.com resolves to 65.9.180.74 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.audible.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.audible.com/

### 4. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** i18n-prefs, lc-main, currentSourceCode, originalSourceCode set without Secure on https://www.audible.com/

### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** session-id, session-id-time, i18n-prefs, lc-main, ubid-main, lopAdbl, currentSourceCode, originalSourceCode, isFirstVisitAdbl set without HttpOnly on https://www.audible.com/

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter plink on https://www.audible.com/ep/audiobooks reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter pageLoadId on https://www.audible.com/ep/audiobooks reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter creativeId on https://www.audible.com/ep/audiobooks reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.audible.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.audible.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.audible.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.audible.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.audible.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.audible.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: audible.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 16. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.audible.com/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
