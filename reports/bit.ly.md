# Security Audit Report — bit.ly

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bit.ly/ |
| Bug bounty program | Bitly |
| Listed scope domain | bit.ly |
| Test date | 2026-09-29 17:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 5, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /pages/home which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://bitly.com/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** _xsrf set without HttpOnly on https://bitly.com/

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter categories on https://bitly.com/pages/marketplace reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: bit.ly + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://bitly.com/

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://bitly.com/

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

### 9. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://bitly.com/.well-known/security.txt returned 200 (95 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)

- I22 /pages/home (finding 1, MEDIUM -> LOW): now returns **404** "Bitly | Page Not Found | 404" (6,071 B soft-404 page) at the gate; the scanner had seen 200 at scan time. Either way no hidden sensitive content.
