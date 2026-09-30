# Security Audit Report — theatlantic.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://theatlantic.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | theatlantic.com |
| Test date | 2026-09-30 03:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 4, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://theatlantic.com/

### 2. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://theatlantic.com/

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** is_gdpr, kppid, atl_uuid set without Secure on https://theatlantic.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** atl_trackid, is_gdpr, kppid, atl_uuid, blaize_session, blaize_tracking_id set without HttpOnly on https://theatlantic.com/

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://theatlantic.com/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
