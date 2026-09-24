# Security Audit Report — forbes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://forbes.com/ |
| Bug bounty program | Forbes |
| Listed scope domain | forbes.com |
| Test date | 2026-09-24 08:36 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 2, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies without Secure flag | CWE-614 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |

## Detailed findings

### 1. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** VWO set without Secure on https://www.forbes.com/

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** VWO set without HttpOnly on https://www.forbes.com/

### 3. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.forbes.com/

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
