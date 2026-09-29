# Security Audit Report — sony.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sony.net/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | sony.net |
| Test date | 2026-09-29 16:39 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 2, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 3 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.sony.net/

### 2. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.sony.net/search reflects input verbatim in body context; encoding boundary not confirmed.

### 3. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.sony.net/

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.sony.net/

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: Apache

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
