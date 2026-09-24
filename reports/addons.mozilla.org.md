# Security Audit Report — addons.mozilla.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://addons.mozilla.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | addons.mozilla.org |
| Test date | 2026-09-24 12:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 1, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 2 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: addons.mozilla.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 2. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://addons.mozilla.org/en-US/firefox/

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
