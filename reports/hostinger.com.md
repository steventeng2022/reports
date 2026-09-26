# Security Audit Report — hostinger.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hostinger.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hostinger.com |
| Test date | 2026-09-26 14:05 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 1, Low: 6, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 6 | low | I10 | OpenAPI spec exposed | CWE-538 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | I23 | XML sitemap exposes 1901 indexed URLs | CWE-200 |
| 11 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /domain-name-results which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.hostinger.com/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.hostinger.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.hostinger.com/

### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** cookie_consent, cookie_consent_country, possible_opt_out_from_auto_consent, auto_filled_consent, hostingerDeviceId, hostingerDeviceIdTs, amplitude_session_id, persistence_hash, hwebsites-exp-assignments set without HttpOnly on https://www.hostinger.com/

### 6. [LOW] OpenAPI spec exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://www.hostinger.com/openapi.json returned 200 (296566 bytes) with a matching signature.

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: hostinger.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.hostinger.com/

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.hostinger.com/

### 10. [INFO] XML sitemap exposes 1901 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.hostinger.com/sitemap.xml returns a sitemap with 1901 URLs, aiding enumeration of the site surface.

### 11. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.hostinger.com/.well-known/security.txt returned 200 (225 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
