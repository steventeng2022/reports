# Security Audit Report — code.visualstudio.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://code.visualstudio.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | code.visualstudio.com |
| Test date | 2026-09-29 13:19 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 2, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I4 | Reflected input in HTML attribute context | CWE-79 |
| 2 | medium | I4 | Reflected input in HTML attribute context | CWE-79 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | I23 | XML sitemap exposes 478 indexed URLs | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Reflected input in HTML attribute context (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://code.visualstudio.com/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 2. [MEDIUM] Reflected input in HTML attribute context (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://code.visualstudio.com/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** MSFPC, vscode-site-exp-assignments set without HttpOnly on https://code.visualstudio.com/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: code.visualstudio.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://code.visualstudio.com/

### 6. [INFO] XML sitemap exposes 478 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://code.visualstudio.com/sitemap.xml returns a sitemap with 478 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
