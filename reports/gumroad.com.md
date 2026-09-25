# Security Audit Report — gumroad.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gumroad.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gumroad.com |
| Test date | 2026-09-25 16:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 9, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H4 | No clickjacking protection | CWE-1023 |
| 2 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I10 | /api returns 200 with an API interface | CWE-538 |
| 9 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://gumroad.com/

### 2. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter tags on https://gumroad.com/3d reflects input verbatim in body context; encoding boundary not confirmed.

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter tags on https://gumroad.com/audio reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter tags on https://gumroad.com/comics-and-graphic-novels reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter tags on https://gumroad.com/business-and-money reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter tags on https://gumroad.com/design reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter tags on https://gumroad.com/drawing-and-painting reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] /api returns 200 with an API interface (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://gumroad.com/api returned 200 (10329 bytes) with a matching signature.

### 9. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: gumroad.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://gumroad.com/

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
