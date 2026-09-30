# Security Audit Report — change.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://change.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | change.org |
| Test date | 2026-09-30 04:34 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **16** (High: 0, Medium: 6, Low: 6, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I4 | Reflected input in HTML attribute context | CWE-79 |
| 2 | medium | I4 | Reflected input in HTML attribute context | CWE-79 |
| 3 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 4 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 5 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 6 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 13 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |
| 16 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Reflected input in HTML attribute context (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.change.org/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 2. [MEDIUM] Reflected input in HTML attribute context (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.change.org/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 3. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain dev.change.org resolves to 65.9.180.101 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 4. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain staging.change.org resolves to 65.9.180.11 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 5. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain old.change.org resolves to 65.9.180.115 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 6. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.change.org resolves to 3.169.121.53 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter source_location on https://www.change.org/impact-stories/10492133 reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter source_location on https://www.change.org/impact-stories/34968392 reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter source_location on https://www.change.org/impact-stories/35740889 reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter source_location on https://www.change.org/impact-stories/36872619 reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter source_location on https://www.change.org/impact-stories/37815770 reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: change.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 13. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.change.org/

### 14. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.change.org/

### 15. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx/1.31.3

### 16. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.change.org/.well-known/security.txt returned 200 (206 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
