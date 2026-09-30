# Security Audit Report — repubblica.it

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://repubblica.it/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | repubblica.it |
| Test date | 2026-09-30 05:59 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 2, Low: 5, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |

## Detailed findings

### 1. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.repubblica.it resolves to 54.192.248.20 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain shop.repubblica.it resolves to 54.192.248.60 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.repubblica.it/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.repubblica.it/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter where on https://quotidiano.repubblica.it/edicola/profilo/newsletter.jsp reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter testata on https://quotidiano.repubblica.it/edicola/profilo/newsletter.jsp reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: repubblica.it + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.repubblica.it/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
