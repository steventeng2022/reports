# Security Audit Report — vanmiubeauty.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vanmiubeauty.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | vanmiubeauty.com |
| Test date | 2026-09-29 20:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 4, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | I10 | WordPress login page exposed | CWE-538 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | T2 | TLS certificate expiring within 43 days | CWE-295 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://vanmiubeauty.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://vanmiubeauty.com/

### 3. [LOW] WordPress login page exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://vanmiubeauty.com/wp-login.php returned 200 (12302 bytes) with a matching signature.

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: vanmiubeauty.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] TLS certificate expiring within 43 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for vanmiubeauty.com (CN=vanmiubeauty.com) valid_to Nov 11 14:29:38 2026 GMT.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
