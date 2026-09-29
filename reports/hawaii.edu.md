# Security Audit Report — hawaii.edu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hawaii.edu/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hawaii.edu |
| Test date | 2026-09-29 13:19 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 8, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | Site served over plain HTTP without redirect to HTTPS | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | info | T2 | TLS certificate expiring within 40 days | CWE-295 |
| 10 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Site served over plain HTTP without redirect to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://hawaii.edu/ returned 200 directly (no 301/302 to HTTPS); content and cookies transit unencrypted.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://hawaii.edu/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://hawaii.edu/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://hawaii.edu/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://hawaii.edu/search reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://hawaii.edu/search reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://hawaii.edu/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://hawaii.edu/search reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [INFO] TLS certificate expiring within 40 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for hawaii.edu (CN=www.hawaii.edu) valid_to Nov  7 23:59:59 2026 GMT.

### 10. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://hawaii.edu/

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://hawaii.edu/

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: Apache/2.4.62 (Red Hat Enterprise Linux)

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
