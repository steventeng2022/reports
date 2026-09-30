# Security Audit Report — arxiv.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://arxiv.org/ |
| Bug bounty program | arXiv |
| Listed scope domain | arxiv.org |
| Test date | 2026-09-30 04:59 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 1, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | T2 | TLS certificate expiring within 15 days | CWE-295 |
| 3 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://arxiv.org/

### 2. [INFO] TLS certificate expiring within 15 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for arxiv.org (CN=arxiv.org) valid_to Oct 15 01:46:52 2026 GMT.

### 3. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://arxiv.org/

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://arxiv.org/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
