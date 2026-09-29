# Security Audit Report — lg.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lg.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | lg.com |
| Test date | 2026-09-29 17:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 1, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.lg.com/

### 2. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.lg.com/

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.lg.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
