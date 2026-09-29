# Security Audit Report — db.tt

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://db.tt/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | db.tt |
| Test date | 2026-09-29 13:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 3, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies without Secure flag | CWE-614 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 4 | info | T2 | TLS certificate expiring within 16 days | CWE-295 |
| 5 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |
| 6 | info | I26 | OpenID configuration exposed (identity endpoints enumerable) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** locale set without Secure on https://www.dropbox.com/

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** __Host-js_csrf, locale set without HttpOnly on https://www.dropbox.com/

### 3. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: db.tt + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 4. [INFO] TLS certificate expiring within 16 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.dropbox.com (CN=*.app.dropbox.com) valid_to Oct 14 23:59:59 2026 GMT.

### 5. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.dropbox.com/.well-known/security.txt returned 200 (524 bytes) with a matching signature.

### 6. [INFO] OpenID configuration exposed (identity endpoints enumerable) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.dropbox.com/.well-known/openid-configuration returned 200 (825 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
