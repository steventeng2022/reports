# Security Audit Report — otto.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://otto.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | otto.de |
| Test date | 2026-09-24 13:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 1, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on / | CWE-942 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** visitorId, BrowserId, csp set without HttpOnly on https://www.otto.de/

### 3. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: otto.de + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.otto.de/

### 5. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on / (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.otto.de/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
