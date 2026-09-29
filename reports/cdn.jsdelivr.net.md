# Security Audit Report — cdn.jsdelivr.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cdn.jsdelivr.net/ |
| Bug bounty program | jsDelivr |
| Listed scope domain | cdn.jsdelivr.net |
| Test date | 2026-09-29 15:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 3, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 4 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.jsdelivr.com/

### 2. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.jsdelivr.com/

### 3. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: cdn.jsdelivr.net + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 4. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.jsdelivr.com/

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.jsdelivr.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
