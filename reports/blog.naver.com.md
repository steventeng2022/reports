# Security Audit Report — blog.naver.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blog.naver.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | blog.naver.com |
| Test date | 2026-09-29 12:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 3, Low: 6, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I26 | Backup archive (backup.zip) exposed | CWE-538 |
| 2 | medium | I26 | Site archive (site.zip) exposed | CWE-538 |
| 3 | medium | I26 | Website archive exposed | CWE-538 |
| 4 | low | T3 | HTTP redirect does not go to HTTPS | CWE-319 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | I10 | macOS .DS_Store file exposed (directory listing metadata) | CWE-538 |
| 9 | low | I26 | WordPress plugins directory responds (plugin enumeration) | CWE-200 |
| 10 | info | T2 | TLS certificate expiring within 32 days | CWE-295 |
| 11 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 12 | info | I26 | humans.txt exposed (team/contact enumeration) | CWE-200 |
| 13 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Backup archive (backup.zip) exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET http://section.blog.naver.com/backup.zip returned 200 (2652 bytes) with a matching signature.

### 2. [MEDIUM] Site archive (site.zip) exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET http://section.blog.naver.com/site.zip returned 200 (2652 bytes) with a matching signature.

### 3. [MEDIUM] Website archive exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET http://section.blog.naver.com/website.zip returned 200 (2652 bytes) with a matching signature.

### 4. [LOW] HTTP redirect does not go to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://blog.naver.com/ redirected to http://section.blog.naver.com (not an HTTPS URL).

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://section.blog.naver.com/

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on http://section.blog.naver.com/

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on http://section.blog.naver.com/

### 8. [LOW] macOS .DS_Store file exposed (directory listing metadata) (`I10`)

- **CWE:** CWE-538
- **Detail:** GET http://section.blog.naver.com/.DS_Store returned 200 (2652 bytes) with a matching signature.

### 9. [LOW] WordPress plugins directory responds (plugin enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET http://section.blog.naver.com/wp-content/plugins/ returned 200 (2652 bytes) with a matching signature.

### 10. [INFO] TLS certificate expiring within 32 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for section.blog.naver.com (CN=ssl.pstatic.net) valid_to Oct 30 23:59:59 2026 GMT.

### 11. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on http://section.blog.naver.com/

### 12. [INFO] humans.txt exposed (team/contact enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET http://section.blog.naver.com/humans.txt returned 200 (2652 bytes) with a matching signature.

### 13. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET http://section.blog.naver.com/.well-known/security.txt returned 200 (2652 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
