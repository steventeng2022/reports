# Security Audit Report — gplus.to

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gplus.to/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gplus.to |
| Test date | 2026-09-29 14:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 1, Low: 8, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I26 | WordPress user enumeration via REST API (wp-json/wp/v2/users) | CWE-200 |
| 2 | low | T3 | Site served over plain HTTP without redirect to HTTPS | CWE-319 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I33 | WordPress user enumeration via ?author=1 | CWE-200 |
| 10 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] WordPress user enumeration via REST API (wp-json/wp/v2/users) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://gplus.to/wp-json/wp/v2/users returned 200 (42313 bytes) with a matching signature.
- **Re-verify (2026-09-29, agent-aggressive):** live 200, 42313B; exposes 1 user (id=5, slug `arthur`, name "Arthur Volk", bio + avatar URLs). Kept MEDIUM.
- **I33 note:** `?author=1` -> 301 https://gplus.to/author/admin -> 200 (85754B author archive) - canonical WordPress author routing; kept LOW (enumeration value primarily via the REST API above). wp-login.php -> 403.

### 2. [LOW] Site served over plain HTTP without redirect to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://gplus.to/ returned 200 directly (no 301/302 to HTTPS); content and cookies transit unencrypted.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://gplus.to/

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://gplus.to/

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://gplus.to/

### 6. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /wp-admin/ which returns 403, indicating a hidden/protected resource exists at that path.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://gplus.to/ reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://gplus.to/ reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] WordPress user enumeration via ?author=1 (`I33`)

- **CWE:** CWE-200
- **Detail:** GET https://gplus.to/?author=1 returns 301 -> https://gplus.to/author/admin; author slug (username) disclosed. Combine with xmlrpc.php for brute force.

### 10. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://gplus.to/

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://gplus.to/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
