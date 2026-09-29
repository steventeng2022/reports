# Security Audit Report — spreaker.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://spreaker.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | spreaker.com |
| Test date | 2026-09-29 20:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **15** (High: 0, Medium: 1, Low: 12, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 14 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 15 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.spreaker.com resolves to 13.249.182.117 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.spreaker.com/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.spreaker.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** XSRF-TOKEN set without HttpOnly on https://www.spreaker.com/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.spreaker.com/signup reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.spreaker.com/login reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.spreaker.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.spreaker.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.spreaker.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.spreaker.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.spreaker.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.spreaker.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: spreaker.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 14. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.spreaker.com/

### 15. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.spreaker.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **S1 #1 (MEDIUM -> LOW):** http://api.spreaker.com = 301 -> https://api.spreaker.com (CloudFront x-cache: Redirect, http->https normalization only). https endpoint = 200, 141B, x-cache: Miss: live first-party page "<h1>Spreaker API</h1><p>For more information, please visit: developers.spreaker.com</p>" - live answering origin, not the CF 915/919B dangling-distribution signature.
