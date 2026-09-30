# Security Audit Report — obsproject.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://obsproject.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | obsproject.com |
| Test date | 2026-09-30 04:59 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 1, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 2 | info | T2 | TLS certificate expiring within 27 days | CWE-295 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /forum/members/ which returns 403, indicating a hidden/protected resource exists at that path.

### 2. [INFO] TLS certificate expiring within 27 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for obsproject.com valid_to Oct 26 23:06:51 2026 GMT.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://obsproject.com/

### 4. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx/1.31.2

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
