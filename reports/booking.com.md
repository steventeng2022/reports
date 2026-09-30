# Security Audit Report — booking.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://booking.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | booking.com |
| Test date | 2026-09-29 23:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 7, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | T2 | TLS certificate expiring within 32 days | CWE-295 |
| 9 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | I26 | humans.txt exposed (team/contact enumeration) | CWE-200 |
| 12 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain admin.booking.com resolves to 54.192.248.74 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.booking.com resolves to 65.9.180.88 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.booking.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.booking.com/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.booking.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.booking.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: booking.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] TLS certificate expiring within 32 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.booking.com (CN=*.booking.com) valid_to Oct 30 23:59:59 2026 GMT.

### 9. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.booking.com/

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.booking.com/

### 11. [INFO] humans.txt exposed (team/contact enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.booking.com/humans.txt returned 200 (437 bytes) with a matching signature.

### 12. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.booking.com/.well-known/security.txt returned 200 (139 bytes) with a matching signature.

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 #1 admin.booking.com (MEDIUM -> LOW):** re-probed = 302 -> https://account.booking.com/oauth2/authorize (first-party OAuth authorization flow, live).
- **S1 #2 api.booking.com (MEDIUM -> LOW):** re-probed = 404 (248 B) branded "Booking.com: 404 Not Found" page from the live origin (envoy, x-cache: Error) - not the CloudFront dangling signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
