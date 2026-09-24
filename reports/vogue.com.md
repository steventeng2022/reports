# Security Audit Report — vogue.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vogue.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | vogue.com |
| Test date | 2026-09-24 12:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 1, Medium: 0, Low: 3, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I7 | Server-side template injection (SSTI) | CWE-94 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Server-side template injection (SSTI) (`I7`)

- **CWE:** CWE-94
- **Detail:** Parameter q on https://www.vogue.com/search: payload #{17*19} is evaluated server-side (response contains 323; control #{17*18} contains 306 instead; token not reflected).

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.vogue.com/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** xid1, CN_segments, CN_xid, CN_geo_country_code set without HttpOnly on https://www.vogue.com/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: vogue.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.vogue.com/

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
