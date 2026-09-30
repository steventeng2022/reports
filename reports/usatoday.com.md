# Security Audit Report — usatoday.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://usatoday.com/ |
| Bug bounty program | USA Today |
| Listed scope domain | usatoday.com |
| Test date | 2026-09-30 03:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H4 | No clickjacking protection | CWE-1023 |
| 2 | info | T2 | TLS certificate expiring within 32 days | CWE-295 |
| 3 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://usatoday.com/

### 2. [INFO] TLS certificate expiring within 32 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for usatoday.com (CN=usatoday.com) valid_to Oct 31 06:54:24 2026 GMT.

### 3. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://usatoday.com/

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://usatoday.com/

### 5. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://usatoday.com/.well-known/security.txt returned 200 (346 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
