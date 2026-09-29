# Security Audit Report — nodejs.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nodejs.org/ |
| Bug bounty program | OpenJS Foundation |
| Listed scope domain | nodejs.org |
| Test date | 2026-09-29 20:24 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 2, Low: 3, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | T2 | TLS certificate expiring within 25 days | CWE-295 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | I23 | XML sitemap exposes 176 indexed URLs | CWE-200 |
| 9 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /dist/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.nodejs.org resolves to 65.9.180.94 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://nodejs.org/en

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://nodejs.org/en

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: nodejs.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] TLS certificate expiring within 25 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for nodejs.org (CN=*.nodejs.org) valid_to Oct 23 23:59:59 2026 GMT.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://nodejs.org/en

### 8. [INFO] XML sitemap exposes 176 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://nodejs.org/sitemap.xml returns a sitemap with 176 URLs, aiding enumeration of the site surface.

### 9. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://nodejs.org/.well-known/security.txt returned 200 (136 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
