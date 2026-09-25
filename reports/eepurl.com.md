# Security Audit Report — eepurl.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eepurl.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | eepurl.com |
| Test date | 2026-09-24 19:10 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 3, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | info | T2 | TLS certificate expiring within 38 days | CWE-295 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://eepurl.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on http://eepurl.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on http://eepurl.com/

### 4. [INFO] TLS certificate expiring within 38 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for eepurl.com (CN=wildcardsan2.mailchimp.com) valid_to Oct 31 23:59:59 2026 GMT.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on http://eepurl.com/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on http://eepurl.com/

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
