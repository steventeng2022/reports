# Security Audit Report — 9to5mac.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://9to5mac.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | 9to5mac.com |
| Test date | 2026-09-30 03:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 11, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I33 | WordPress user enumeration via ?author=1 | CWE-200 |
| 11 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 12 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://9to5mac.com/

### 2. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/2026/09/29/apple-pay-now-rolling-out-to-axis-bank-customers-in-india/ reflects input verbatim in body context; encoding boundary not confirmed.

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/2026/09/29/bank-of-america-says-metas-muse-highlights-a-new-risk-for-apples-services-revenue/ reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/2026/09/29/apple-tv-renews-french-drama-careme-for-season-two/ reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/poll-post/how-do-you-plan-on-buying-your-next-iphone/ reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/2026/09/29/daily-september-29-2026/ reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://9to5mac.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://9to5mac.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://9to5mac.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] WordPress user enumeration via ?author=1 (`I33`)

- **CWE:** CWE-200
- **Detail:** GET https://9to5mac.com/?author=1 returns 301 -> https://9to5mac.com/author/seth844/; author slug (username) disclosed. Combine with xmlrpc.php for brute force.

### 11. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: 9to5mac.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 12. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://9to5mac.com/

### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://9to5mac.com/

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
