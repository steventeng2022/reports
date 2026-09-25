# Security Audit Report — ietf.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ietf.org/ |
| Bug bounty program | IETF |
| Listed scope domain | ietf.org |
| Test date | 2026-09-25 16:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 1, Low: 4, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | I23 | XML sitemap exposes 989 indexed URLs | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.ietf.org/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.ietf.org/

### 4. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.ietf.org/staging/ returns 200 with content different from the main site (4840 bytes); legacy deployments often carry weaker controls.

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: ietf.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] XML sitemap exposes 989 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.ietf.org/sitemap.xml returns a sitemap with 989 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
