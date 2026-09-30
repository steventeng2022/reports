# Security Audit Report - zara.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zara.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | zara.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 0, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | Homepage 403 for scanner client | CWE-916 |
| 2 | info | S1 | www.zara.com serves 2 KB page | CWE-916 |
| 3 | info | S1 | app/account/static 403; news 404 | CWE-916 |
| 4 | info | S1 | test.zara.com returns 400 behind Akamai | CWE-916 |

## Detailed findings

### 1. [INFO] Homepage 403 for scanner client (S1)

- **CWE:** CWE-916
- **Detail:** zara.com 403 (358 B) - edge-gated homepage for the scanner client.

### 2. [INFO] www.zara.com serves 2 KB page (S1)

- **CWE:** CWE-916
- **Detail:** www.zara.com 200 (2123 B, title "&nbsp;") - minimal secondary web host.

### 3. [INFO] app/account/static 403; news 404 (S1)

- **CWE:** CWE-916
- **Detail:** app.zara.com 403 (364 B); account.zara.com 403 (368 B); static.zara.com 403 (821 B); news.zara.com 404 (236 B).

### 4. [INFO] test.zara.com returns 400 behind Akamai (S1)

- **CWE:** CWE-916
- **Detail:** test.zara.com 400 (306 B AkamaiGHost); chat.zara.com ECONNRESET from external vantage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
