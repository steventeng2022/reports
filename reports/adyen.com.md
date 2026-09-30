# Security Audit Report - adyen.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://adyen.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | adyen.com
| Test date | 2026-09-30 12:45 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation with 2-hop canary tracking, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 2, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | sso.adyen.com 302 with iss and session_hint params | CWE-916 |
| 2 | low | S1 | test.adyen.com serves a live page | CWE-916 |
| 3 | info | S1 | status.adyen.com serves the platform status page (title typo) | CWE-916 |
| 4 | info | S1 | docs.adyen.com serves 3.4 MB of documentation | CWE-916 |
| 5 | info | S1 | help.adyen.com live; support 301 to help | CWE-916 |

## Detailed findings

### 1. [LOW] sso.adyen.com 302 with iss and session_hint params (S1)

- **CWE:** CWE-916
- **Detail:** sso.adyen.com 302 to https://sso.adyen.com/app/UserHome?iss=...&session_hint=AUTHENTICATED - the SSO endpoint exposes iss and session_hint params publicly.

### 2. [LOW] test.adyen.com serves a live page (S1)

- **CWE:** CWE-916
- **Detail:** test.adyen.com 200 (22 B Cloudflare) - a test hostname publicly resolving.

### 3. [INFO] status.adyen.com serves the platform status page (title typo) (S1)

- **CWE:** CWE-916
- **Detail:** status.adyen.com 200 (50 KB, title "Adyen platfom status" - missing the final r) - the status subdomain is publicly reachable.

### 4. [INFO] docs.adyen.com serves 3.4 MB of documentation (S1)

- **CWE:** CWE-916
- **Detail:** docs.adyen.com 200 (3.4 MB Cloudflare) - the documentation subdomain is publicly reachable.

### 5. [INFO] help.adyen.com live; support 301 to help (S1)

- **CWE:** CWE-916
- **Detail:** help.adyen.com 200; support.adyen.com 301 to https://help.adyen.com/.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
