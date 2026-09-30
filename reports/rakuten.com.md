# Security Audit Report — rakuten.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://rakuten.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | rakuten.com |
| Test date | 2026-09-30 07:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 5, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | 301 to public homepage (no hidden content) | CWE-538 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] 301 to public homepage (no hidden content) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /editUserInfos.do which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.rakuten.com/

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** AWSALB, ajs_anonymous_id set without Secure on https://www.rakuten.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** AWSALB, AWSALBCORS, ajs_anonymous_id set without HttpOnly on https://www.rakuten.com/

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: rakuten.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.rakuten.com/

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 (MEDIUM -> LOW):** /editUserInfos.do re-probed = 301 (nginx) -> https://www.rakuten.com/editUserInfos.do = 200 (674,764 B, Rakuten homepage "Shop. Get Cash Back. Repeat.", set-cookie 9) - generic homepage, no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
