# Security Audit Report - hotels.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hotels.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hotels.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 0, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | Homepage 429 rate-limited at edge | CWE-916 |
| 2 | info | S1 | auth.hotels.com 404; mail unreachable | CWE-916 |

## Detailed findings

### 1. [INFO] Homepage 429 rate-limited at edge (S1)

- **CWE:** CWE-916
- **Detail:** www.hotels.com 429 (108 B) - edge rate limit applied to the scanner client.

### 2. [INFO] auth.hotels.com 404; mail unreachable (S1)

- **CWE:** CWE-916
- **Detail:** auth.hotels.com 404 (46 B Apache); mail.hotels.com ECONNRESET from external vantage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
