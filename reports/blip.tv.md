# Security Audit Report — blip.tv

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blip.tv/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | blip.tv |
| Test date | 2026-09-29 18:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 6, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | C1 | Cookies without Secure flag | CWE-614 |
| 5 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 6 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 7 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.disney.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.disney.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.disney.com/

### 4. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** country, SWID, userab_1 set without Secure on https://www.disney.com/

### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** country, SWID, userab_1 set without HttpOnly on https://www.disney.com/

### 6. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: blip.tv + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 7. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.disney.com/

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.disney.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
