# Security Audit Report — a2hosting.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://a2hosting.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | a2hosting.com |
| Test date | 2026-09-29 16:39 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 1, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: a2hosting.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
