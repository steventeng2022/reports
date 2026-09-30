# Security Audit Report — redcross.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://redcross.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | redcross.org |
| Test date | 2026-09-30 04:34 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 2, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 2 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H6 | Server technology disclosure | CWE-200 |
| 5 | info | I23 | XML sitemap exposes 2026 indexed URLs | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** AWSALBAPP-0, AWSALBAPP-1, AWSALBAPP-2, AWSALBAPP-3 set without HttpOnly on https://www.redcross.org/

### 2. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: redcross.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.redcross.org/

### 4. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: Apache

### 5. [INFO] XML sitemap exposes 2026 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.redcross.org/sitemap.xml returns a sitemap with 2026 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
