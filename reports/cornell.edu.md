# Security Audit Report - cornell.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cornell.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cornell.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 1, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | news.cornell.edu serves Cornell Chronicle | CWE-916 |
| 2 | info | S1 | files.cornell.edu unreachable | CWE-916 |

## Detailed findings

### 1. [LOW] news.cornell.edu serves Cornell Chronicle (S1)

- **CWE:** CWE-916
- **Detail:** news.cornell.edu 200 (67506 B nginx) first-party news site.

### 2. [INFO] files.cornell.edu unreachable (S1)

- **CWE:** CWE-916
- **Detail:** files.cornell.edu ECONNRESET from external vantage - stale record still resolving.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
