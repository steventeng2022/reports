# Security Audit Report — relapse.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://relapse.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | relapse.com |
| Test date | 2026-09-30 02:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 1, Low: 8, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | C1 | Cookies without Secure flag | CWE-614 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I11 | GraphQL introspection enabled on /api/graphql | CWE-200 |
| 9 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 10 | info | T2 | TLS certificate expiring within 40 days | CWE-295 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | I26 | OpenID configuration exposed (identity endpoints enumerable) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /cart/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** localization, cart_currency set without Secure on https://www.relapse.com/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** localization, cart_currency set without HttpOnly on https://www.relapse.com/

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.relapse.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.relapse.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.relapse.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.relapse.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] GraphQL introspection enabled on /api/graphql (`I11`)

- **CWE:** CWE-200
- **Detail:** POST https://www.relapse.com/api/graphql with {__schema{types{name}}} returns the full type map.

### 9. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: relapse.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 10. [INFO] TLS certificate expiring within 40 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.relapse.com (CN=www.relapse.com) valid_to Nov  8 11:28:31 2026 GMT.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.relapse.com/

### 12. [INFO] OpenID configuration exposed (identity endpoints enumerable) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.relapse.com/.well-known/openid-configuration returned 200 (1355 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
