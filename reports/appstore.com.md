# Security Audit Report — appstore.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://appstore.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | appstore.com |
| Test date | 2026-09-29 19:33 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies without Secure flag | CWE-614 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** geo set without Secure on https://apps.apple.com/today

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** geo set without HttpOnly on https://apps.apple.com/today

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://apps.apple.com/today

### 4. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://apps.apple.com/.well-known/security.txt returned 200 (2383 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
