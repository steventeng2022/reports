# Security Audit Report — thelancet.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://thelancet.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | thelancet.com |
| Test date | 2026-09-30 00:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://thelancet.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on http://thelancet.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on http://thelancet.com/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: thelancet.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on http://thelancet.com/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on http://thelancet.com/

### 7. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET http://thelancet.com/.well-known/security.txt returned 200 (65 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
