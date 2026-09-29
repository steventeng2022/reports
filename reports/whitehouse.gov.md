# Security Audit Report — whitehouse.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://whitehouse.gov/ |
| Bug bounty program | White House |
| Listed scope domain | whitehouse.gov |
| Test date | 2026-09-29 16:16 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 1, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 2 | info | T2 | TLS certificate expiring within 35 days | CWE-295 |
| 3 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: whitehouse.gov + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 2. [INFO] TLS certificate expiring within 35 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.whitehouse.gov (CN=whitehouse.gov) valid_to Nov  2 18:59:46 2026 GMT.

### 3. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
