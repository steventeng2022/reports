# Security Audit Report — mlb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mlb.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mlb.com |
| Test date | 2026-09-25 13:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 3, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 3 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.mlb.com/

### 2. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.mlb.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 3. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: mlb.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
