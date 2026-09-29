# Security Audit Report — gimp.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gimp.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gimp.org |
| Test date | 2026-09-29 14:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 1, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 2 | info | H6 | Server technology disclosure | CWE-200 |
| 3 | info | I23 | XML sitemap exposes 402 indexed URLs | CWE-200 |

## Detailed findings

### 1. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: gimp.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 2. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: Apache/2.4.62 (Red Hat Enterprise Linux) OpenSSL/3.5.8

### 3. [INFO] XML sitemap exposes 402 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.gimp.org/sitemap.xml returns a sitemap with 402 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
