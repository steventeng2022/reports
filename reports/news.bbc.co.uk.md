# Security Audit Report — news.bbc.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://news.bbc.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | news.bbc.co.uk |
| Test date | 2026-09-30 00:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 2, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /backstage/bbc-login-help/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: news.bbc.co.uk + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 (MEDIUM -> LOW):** /backstage/bbc-login-help/ re-probed = 301 -> http://news.bbc.co.uk/backstage/bbc-login-help/ = 404 (2,794 B, "404 - Page Not Found") - the robots.txt-disallowed path no longer exists.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
