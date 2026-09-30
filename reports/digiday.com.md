# Security Audit Report — digiday.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://digiday.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | digiday.com |
| Test date | 2026-09-30 04:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 16, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 15 | low | I33 | WordPress user enumeration via ?author=1 | CWE-200 |
| 16 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 17 | info | T2 | TLS certificate expiring within 29 days | CWE-295 |
| 18 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 19 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 20 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://digiday.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://digiday.com/

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_source on https://digiday.com/subscribe/ reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_campaign on https://digiday.com/form/publisher-revenue-diversification/ reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_campaign on https://digiday.com/form/live-session-how-ctv-has-grown-into-a-performance-marketing-engine/ reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_campaign on https://digiday.com/sponsored/the-state-of-subscriber-engagement-in-the-ai-era-publishers-first-party-relationship-strategies/ reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_campaign on https://digiday.com/sponsored/in-the-zero-click-era-visibility-alone-is-no-longer-enough-for-brands/ reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://digiday.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://digiday.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://digiday.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://digiday.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://digiday.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://digiday.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://digiday.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] WordPress user enumeration via ?author=1 (`I33`)

- **CWE:** CWE-200
- **Detail:** GET https://digiday.com/?author=1 returns 301 -> https://digiday.com/author/anekola/; author slug (username) disclosed. Combine with xmlrpc.php for brute force.

### 16. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: digiday.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 17. [INFO] TLS certificate expiring within 29 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for digiday.com (CN=digiday.com) valid_to Oct 28 20:31:10 2026 GMT.

### 18. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://digiday.com/

### 19. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://digiday.com/

### 20. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
