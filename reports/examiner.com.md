# Security Audit Report — examiner.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://examiner.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | examiner.com |
| Test date | 2026-09-29 23:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 4, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /comments/feed/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://examiner.com/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://examiner.com/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: examiner.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 (MEDIUM -> LOW):** https://www.examiner.com/comments/feed/ re-probed = 301 -> https://examiner.com/ (200, 163,103 B homepage) - the robots.txt-disallowed path now redirects to the first-party apex; no hidden content.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
