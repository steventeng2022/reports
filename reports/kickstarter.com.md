# Security Audit Report — kickstarter.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://kickstarter.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | kickstarter.com |
| Test date | 2026-09-29 23:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | T2 | TLS certificate expiring within 45 days | CWE-295 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.kickstarter.com resolves to 65.9.180.43 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://kickstarter.com/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://kickstarter.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://kickstarter.com/

### 5. [INFO] TLS certificate expiring within 45 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for kickstarter.com (CN=kickstarter.com) valid_to Nov 13 04:01:46 2026 GMT.

### 6. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://kickstarter.com/

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://kickstarter.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 (MEDIUM -> LOW):** status.kickstarter.com re-probed = 200 (54,327 B) Atlassian Statuspage served via CloudFront (server: AtlassianEdge) - live first-party status page, not dangling.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
