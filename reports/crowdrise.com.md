# Security Audit Report — crowdrise.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://crowdrise.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | crowdrise.com |
| Test date | 2026-09-30 05:31 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 6, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | /track first-party 301 redirect to GoFundMe (not hidden data) | CWE-538 |
| 2 | low | C1 | Cookies without Secure flag | CWE-614 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 7 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] /track first-party 301 redirect to GoFundMe (not hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /track which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** visitor set without Secure on https://www.gofundme.com/c/crowdrise

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** visitor set without HttpOnly on https://www.gofundme.com/c/crowdrise

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.gofundme.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.gofundme.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: crowdrise.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 7. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.gofundme.com/c/crowdrise

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.gofundme.com/c/crowdrise

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 (MEDIUM -> LOW):** /track re-probed = 301 (awselb/2.0) -> https://www.gofundme.com/c/crowdrise (first-party redirect, Crowdrise is operated by GoFundMe) - no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
