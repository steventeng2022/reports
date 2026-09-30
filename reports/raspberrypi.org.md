# Security Audit Report — raspberrypi.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://raspberrypi.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | raspberrypi.org |
| Test date | 2026-09-30 05:59 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 2, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.raspberrypi.org/

### 2. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: raspberrypi.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
