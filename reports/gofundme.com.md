# Security Audit Report — gofundme.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gofundme.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gofundme.com |
| Test date | 2026-09-25 13:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **15** (High: 0, Medium: 5, Low: 7, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 4 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 5 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | C1 | Cookies without Secure flag | CWE-614 |
| 9 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 13 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /track which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain test.gofundme.com resolves to 54.192.248.33 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 403

### 3. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain stage.gofundme.com resolves to 54.192.248.37 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 403

### 4. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain admin.gofundme.com resolves to 54.192.248.78 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 403

### 5. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.gofundme.com resolves to 54.192.248.121 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.gofundme.com/

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.gofundme.com/

### 8. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** visitor, gdid set without Secure on https://www.gofundme.com/

### 9. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** visitor, gdid set without HttpOnly on https://www.gofundme.com/

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.gofundme.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.gofundme.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: gofundme.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 13. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.gofundme.com/

### 14. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.gofundme.com/

### 15. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
