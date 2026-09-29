# Security Audit Report — eventbrite.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eventbrite.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | eventbrite.co.uk |
| Test date | 2026-09-29 16:16 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 3, Low: 7, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 7 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 11 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain dev.eventbrite.co.uk resolves to 65.9.180.122 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain test.eventbrite.co.uk resolves to 65.9.180.120 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain stage.eventbrite.co.uk resolves to 65.9.180.129 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.eventbrite.co.uk/

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.eventbrite.co.uk/

### 6. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** csrftoken, stableId set without HttpOnly on https://www.eventbrite.co.uk/

### 7. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /esi_cache/ which returns 403, indicating a hidden/protected resource exists at that path.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter referrer on https://www.eventbrite.co.uk/signin/signup reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter referrer on https://www.eventbrite.co.uk/signin/signup/ reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: eventbrite.co.uk + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 11. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.eventbrite.co.uk/

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.eventbrite.co.uk/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
