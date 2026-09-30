# Security Audit Report - hsbc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hsbc.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hsbc.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 0, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | api.hsbc.com returns CloudFront error page | CWE-916 |
| 2 | info | S1 | media.hsbc.com serves empty body | CWE-916 |
| 3 | info | I22 | Hidden form endpoints with unreflected params | CWE-538 |

## Detailed findings

### 1. [INFO] api.hsbc.com returns CloudFront error page (S1)

- **CWE:** CWE-916
- **Detail:** api.hsbc.com 403 (111 B, "Error from cloudfront").

### 2. [INFO] media.hsbc.com serves empty body (S1)

- **CWE:** CWE-916
- **Detail:** media.hsbc.com 200 (0 B).

### 3. [INFO] Hidden form endpoints with unreflected params (I22)

- **CWE:** CWE-538
- **Detail:** /search-results accepts q/query and /api/tables/archive accepts recordcode; token probes accepted without reflection (tokenIdx=-1) and /api/tables/archive?recordcode=... returns 400 (126289 B).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
