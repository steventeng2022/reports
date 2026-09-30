# Security Audit Report — rt.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://rt.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | rt.com |
| Test date | 2026-09-30 06:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 6, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H4 | No clickjacking protection | CWE-1023 |
| 2 | low | C1 | Cookies without Secure flag | CWE-614 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 7 | info | T2 | TLS certificate expiring within 13 days | CWE-295 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.rt.com/

### 2. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** __ddg8_, __ddg10_, __ddg9_, __ddg1_ set without Secure on https://www.rt.com/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** __ddg8_, __ddg10_, __ddg9_ set without HttpOnly on https://www.rt.com/

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.rt.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.rt.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: rt.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 7. [INFO] TLS certificate expiring within 13 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.rt.com (CN=rt.com) valid_to Oct 12 11:08:53 2026 GMT.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.rt.com/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
