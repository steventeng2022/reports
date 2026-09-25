# Security Audit Report — overcast.fm

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://overcast.fm/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | overcast.fm |
| Test date | 2026-09-25 12:02 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
