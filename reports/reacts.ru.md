# Security Audit Report — reacts.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://reacts.ru/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | reacts.ru |
| Test date | 2026-09-24 22:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 2, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | T2 | Expired TLS certificate | CWE-295 |
| 2 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 3 | low | T3 | Site served over plain HTTP without redirect to HTTPS | CWE-319 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Expired TLS certificate (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for reacts.ru (CN=reacts.ru) valid_to Sep  3 22:44:32 2026 GMT is in the past.

### 2. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /js/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 3. [LOW] Site served over plain HTTP without redirect to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://reacts.ru/ returned 200 directly (no 301/302 to HTTPS); content and cookies transit unencrypted.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://reacts.ru/

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://reacts.ru/

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://reacts.ru/

### 7. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://reacts.ru/

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://reacts.ru/

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
