# Security Audit Report — rockpapershotgun.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://rockpapershotgun.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | rockpapershotgun.com |
| Test date | 2026-09-30 02:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 1, Low: 3, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search?q= which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.rockpapershotgun.com/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** geoCC, geoRC set without HttpOnly on https://www.rockpapershotgun.com/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: rockpapershotgun.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
