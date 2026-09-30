# Security Audit Report — ted.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ted.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ted.com |
| Test date | 2026-09-30 01:07 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 7, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.ted.com/

### 2. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /me.json which returns 403, indicating a hidden/protected resource exists at that path.

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter sort on https://www.ted.com/talks reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter topics[0] on https://www.ted.com/talks reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ted.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.ted.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: ted.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx/1.27.5

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
