# Security Audit Report — archive.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://archive.org/ |
| Bug bounty program | Internet Archive |
| Listed scope domain | archive.org |
| Test date | 2026-09-30 05:31 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | Site served over plain HTTP without redirect to HTTPS | CWE-319 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Site served over plain HTTP without redirect to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://archive.org/ returned 200 directly (no 301/302 to HTTPS); content and cookies transit unencrypted.

### 2. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://archive.org/

### 3. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://archive.org/

### 4. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx/1.31.3

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
