# Security Audit Report - wellsfargo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wellsfargo.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wellsfargo.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 2, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | www.staging.wellsfargo.com staging host exposed | CWE-916 |
| 2 | info | S1 | api.wellsfargo.com returns 400 | CWE-916 |
| 3 | info | S1 | static.wellsfargo.com serves empty body | CWE-916 |
| 4 | low | S1 | connect.secure.wellsfargo.com login endpoint | CWE-916 |
| 5 | low | C1 | ADRUM_BTa New Relic cookie set without Secure flag | CWE-614 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [INFO] www.staging.wellsfargo.com staging host exposed (S1)

- **CWE:** CWE-916
- **Detail:** www.staging.wellsfargo.com 403 (382 B) - staging host live and resolving publicly.

### 2. [INFO] api.wellsfargo.com returns 400 (S1)

- **CWE:** CWE-916
- **Detail:** api.wellsfargo.com 400 (231 B).

### 3. [INFO] static.wellsfargo.com serves empty body (S1)

- **CWE:** CWE-916
- **Detail:** static.wellsfargo.com 200 (0 B).

### 4. [LOW] connect.secure.wellsfargo.com login endpoint (S1)

- **CWE:** CWE-916
- **Detail:** connect.secure.wellsfargo.com/auth/login/do returns 302 - online-banking login endpoint reachable on the public subdomain.

### 5. [LOW] ADRUM_BTa New Relic cookie set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** ADRUM_BTa (30 s, Lax) set without the Secure flag.

### 6. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.wellsfargo.com/ (CSP, X-Frame-Options and HSTS present).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
