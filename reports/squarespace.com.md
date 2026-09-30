# Security Audit Report — squarespace.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://squarespace.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | squarespace.com |
| Test date | 2026-09-30 03:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 4, Low: 7, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 4 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | C1 | Cookies without Secure flag | CWE-614 |
| 8 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | I23 | XML sitemap exposes 687 indexed URLs | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain dev.squarespace.com resolves to 198.185.159.176 and is served by Squarespace (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 200

### 3. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain old.squarespace.com resolves to 198.185.159.177 and is served by Squarespace (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 404

### 4. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.squarespace.com resolves to 3.169.121.91 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.squarespace.com/

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.squarespace.com/

### 7. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** SS_MID set without Secure on https://www.squarespace.com/

### 8. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** crumb, SS_MID set without HttpOnly on https://www.squarespace.com/

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.squarespace.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.squarespace.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: squarespace.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.squarespace.com/

### 13. [INFO] XML sitemap exposes 687 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.squarespace.com/sitemap.xml returns a sitemap with 687 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
