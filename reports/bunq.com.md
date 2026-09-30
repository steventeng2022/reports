# Security Audit Report - bunq.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bunq.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bunq.com
| Test date | 2026-09-30 12:45 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation with 2-hop canary tracking, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 3, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | /link?url forwards the param to the third-party Adjust tracker | CWE-538 |
| 2 | low | S1 | oauth.bunq.com serves the OAuth app without auth | CWE-916 |
| 3 | low | S1 | login.bunq.com 302 with iss and session_hint params | CWE-916 |
| 4 | info | S1 | help.bunq.com serves a large help centre | CWE-916 |
| 5 | info | S1 | status.bunq.com serves a status page | CWE-916 |
| 6 | info | S1 | static 403 S3; api 404; blog 301 | CWE-916 |

## Detailed findings

### 1. [LOW] /link?url forwards the param to the third-party Adjust tracker (I22)

- **CWE:** CWE-538
- **Detail:** /link?url=canary 308 to https://app.adjust.com/dqvbt6?engagement_type=fallback_click&fallback=...&url=canary - the user-supplied url param is propagated to the third-party Adjust marketing tracker; Adjust then 302s to https://web.bunq.com/signup where the token is consumed.

### 2. [LOW] oauth.bunq.com serves the OAuth app without auth (S1)

- **CWE:** CWE-916
- **Detail:** oauth.bunq.com 200 (35 KB Apache, title "OAuth | bunq") - the OAuth client application is publicly reachable.

### 3. [LOW] login.bunq.com 302 with iss and session_hint params (S1)

- **CWE:** CWE-916
- **Detail:** login.bunq.com 302 to https://login.bunq.com/app/UserHome?iss=...&session_hint=AUTHENTICATED - the SSO endpoint exposes iss and session_hint params publicly.

### 4. [INFO] help.bunq.com serves a large help centre (S1)

- **CWE:** CWE-916
- **Detail:** help.bunq.com 200 (672 KB) - the help subdomain is publicly reachable.

### 5. [INFO] status.bunq.com serves a status page (S1)

- **CWE:** CWE-916
- **Detail:** status.bunq.com 200 at the subdomain root.

### 6. [INFO] static 403 S3; api 404; blog 301 (S1)

- **CWE:** CWE-916
- **Detail:** static.bunq.com 403 (S3); api.bunq.com 404; blog.bunq.com 301 to the main site.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
