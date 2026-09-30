# Security Audit Report — wa.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wa.me/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wa.me |
| Test date | 2026-09-30 06:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 1, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I10 | Laravel Telescope exposed | CWE-538 |
| 2 | info | T2 | TLS certificate expiring within 10 days | CWE-295 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Laravel Telescope exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://wa.me/telescope returned 200 (106486 bytes) with a matching signature.

### 2. [INFO] TLS certificate expiring within 10 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for wa.me (CN=*.whatsapp.net) valid_to Oct  9 23:59:59 2026 GMT.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://wa.me/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
