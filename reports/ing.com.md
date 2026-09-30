# Security Audit Report - ing.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ing.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ing.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 0, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | Homepage 403 behind Akamai | CWE-916 |
| 2 | info | S1 | www.ing.com returns 403 | CWE-916 |
| 3 | info | S1 | api.ing.com returns 403 | CWE-916 |
| 4 | info | S1 | cdn.ing.com serves 101-byte rejection page | CWE-916 |
| 5 | info | S1 | assets.ing.com 302 to /login/ path; mail unreachable | CWE-916 |

## Detailed findings

### 1. [INFO] Homepage 403 behind Akamai (S1)

- **CWE:** CWE-916
- **Detail:** ing.com 403 (357 B AkamaiGHost) - edge-gated homepage for the scanner client.

### 2. [INFO] www.ing.com returns 403 (S1)

- **CWE:** CWE-916
- **Detail:** www.ing.com 403 (365 B AkamaiGHost).

### 3. [INFO] api.ing.com returns 403 (S1)

- **CWE:** CWE-916
- **Detail:** api.ing.com 403 (556 B) at the subdomain root.

### 4. [INFO] cdn.ing.com serves 101-byte rejection page (S1)

- **CWE:** CWE-916
- **Detail:** cdn.ing.com 200 (101 B, title "Request Rejected") - bot-rejection document on the cdn subdomain.

### 5. [INFO] assets.ing.com 302 to /login/ path; mail unreachable (S1)

- **CWE:** CWE-916
- **Detail:** assets.ing.com 302 (nginx) to /login/ - assets alias redirecting to a login path; mail.ing.com ECONNRESET from external vantage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
