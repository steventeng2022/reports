# Security Audit Report — economictimes.indiatimes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://economictimes.indiatimes.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | economictimes.indiatimes.com |
| Test date | 2026-09-26 05:37 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **14** (High: 0, Medium: 2, Low: 10, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 2 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 13 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://economictimes.indiatimes.com/ with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 2. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /default1.cms which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** geoinfo set without Secure on https://economictimes.indiatimes.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** geoinfo set without HttpOnly on https://economictimes.indiatimes.com/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_source on https://economictimes.indiatimes.com/masterclass reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_source on https://economictimes.indiatimes.com/masterclass/wealth-expo reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_source on https://economictimes.indiatimes.com/awards/product-of-the-year-awards-2026 reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_medium on https://economictimes.indiatimes.com/awards/product-of-the-year-awards-2026 reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_campaign on https://economictimes.indiatimes.com/awards/product-of-the-year-awards-2026 reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_source on https://economictimes.indiatimes.com/masterclass/alphawealthsummit reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter utm_source on https://economictimes.indiatimes.com/masterclass/mutual-funds-workshop reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: economictimes.indiatimes.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 13. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://economictimes.indiatimes.com/

### 14. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://economictimes.indiatimes.com/

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
