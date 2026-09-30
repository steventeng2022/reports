# Security Audit Report — xinhuanet.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://xinhuanet.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | xinhuanet.com |
| Test date | 2026-09-30 03:06 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 5, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | Site served over plain HTTP without redirect to HTTPS | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | T2 | TLS certificate expiring within 27 days | CWE-295 |
| 7 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Site served over plain HTTP without redirect to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://xinhuanet.com/ returned 200 directly (no 301/302 to HTTPS); content and cookies transit unencrypted.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://xinhuanet.com/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://xinhuanet.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://xinhuanet.com/

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: xinhuanet.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] TLS certificate expiring within 27 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for xinhuanet.com (CN=*.news.cn) valid_to Oct 26 07:10:36 2026 GMT.

### 7. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://xinhuanet.com/

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://xinhuanet.com/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
