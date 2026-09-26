# Security Audit Report — xing.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://xing.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | xing.com |
| Test date | 2026-09-26 06:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 7, Low: 4, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 4 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 5 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 6 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 7 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /jobs/posting_clicks which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain dev.xing.com resolves to 3.169.231.34 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain staging.xing.com resolves to 18.154.144.107 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 4. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain beta.xing.com resolves to 18.154.144.78 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 5. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain old.xing.com resolves to 18.154.144.42 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 6. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain admin.xing.com resolves to 65.9.126.104 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 7. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.xing.com resolves to 52.222.244.115 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.xing.com/

### 9. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** xing_csrf_token set without HttpOnly on https://www.xing.com/

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter keywords on https://www.xing.com/jobs/t-quereinsteiger reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: xing.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Reproduction notes

- Scanned 2026-09-26 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
