# Security Audit Report — openstreetmap.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://openstreetmap.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | openstreetmap.org |
| Test date | 2026-09-29 18:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 2, Medium: 3, Low: 3, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I30 | Reflected XSS via attribute breakout (onfocus autofocus) | CWE-79 |
| 2 | high | I30 | Reflected XSS via attribute breakout (onfocus autofocus) | CWE-79 |
| 3 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 4 | medium | I4 | Reflected input in HTML attribute context | CWE-79 |
| 5 | medium | I4 | Reflected input in HTML attribute context | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 9 | info | T2 | TLS certificate expiring within 33 days | CWE-295 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.openstreetmap.org/api | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.openstreetmap.org/api | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.openstreetmap.org/api | CWE-942 |

## Detailed findings

### 1. [HIGH] Reflected XSS via attribute breakout (onfocus autofocus) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.openstreetmap.org/search: injecting "' onfocus=alert(1) autofocus x='" breaks out of the attribute; onfocus fires automatically.

### 2. [HIGH] Reflected XSS via attribute breakout (onfocus autofocus) (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.openstreetmap.org/search: injecting "' onfocus=alert(1) autofocus x='" breaks out of the attribute; onfocus fires automatically.

### 3. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /traces which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 4. [MEDIUM] Reflected input in HTML attribute context (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.openstreetmap.org/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 5. [MEDIUM] Reflected input in HTML attribute context (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.openstreetmap.org/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.openstreetmap.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.openstreetmap.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: openstreetmap.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 9. [INFO] TLS certificate expiring within 33 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.openstreetmap.org (CN=www.openstreetmap.org) valid_to Oct 31 20:33:59 2026 GMT.

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: Apache

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.openstreetmap.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.openstreetmap.org/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.openstreetmap.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.openstreetmap.org/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.openstreetmap.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.openstreetmap.org/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
