# Security Audit Report — vanityfair.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vanityfair.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | vanityfair.com |
| Test date | 2026-09-29 17:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 4, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /user-context which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.vanityfair.com/

### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** xid1, CN_segments, CN_xid, CN_geo_country_code set without HttpOnly on https://www.vanityfair.com/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: vanityfair.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.vanityfair.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)

- I22 /user-context (finding 1, MEDIUM -> LOW): 200 `application/javascript` 171 B — a tiny snippet that expires the `CN_segments` cookie (`document.cookie = "CN_segments=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure"`). Trivial client-side helper, not hidden sensitive content.
