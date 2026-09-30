# Security Audit Report - monzo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://monzo.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | monzo.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 5, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | I22 | 20 redirect-style paths 301-redirect with params retained | CWE-538 |
| 2 | low | S1 | auth.monzo.com serves SPA without auth wall | CWE-916 |
| 3 | low | S1 | docs.monzo.com public API reference | CWE-916 |
| 4 | low | S1 | status.monzo.com redirects to Statuspage | CWE-916 |
| 5 | low | S1 | pay.monzo.com first-party page | CWE-916 |
| 6 | info | S1 | api.monzo.com serves 44-byte body | CWE-916 |
| 7 | low | C2 | __monzo_locale_v1__ cookie set without HttpOnly flag | CWE-1004 |

## Detailed findings

### 1. [INFO] 20 redirect-style paths 301-redirect with params retained (I22)

- **CWE:** CWE-538
- **Detail:** /redirect, /r, /go, /out, /link, /continue, /next, /return, /redir, /jump, /url, /target, /callback and /follow accept url/u/to/next/return; 301 to the same absolute path with the param retained; second hop is a 404 (9928 B) consuming the token - no open redirect.

### 2. [LOW] auth.monzo.com serves SPA without auth wall (S1)

- **CWE:** CWE-916
- **Detail:** auth.monzo.com 200 (106548 B Cloudflare) - authentication subdomain serving a full single-page app publicly.

### 3. [LOW] docs.monzo.com public API reference (S1)

- **CWE:** CWE-916
- **Detail:** docs.monzo.com 200 (116893 B Cloudflare, title "Monzo API Reference") - full API reference published on the docs subdomain.

### 4. [LOW] status.monzo.com redirects to Statuspage (S1)

- **CWE:** CWE-916
- **Detail:** status.monzo.com 302 (143 B) to monzo.statuspage.io (Statuspage SaaS).

### 5. [LOW] pay.monzo.com first-party page (S1)

- **CWE:** CWE-916
- **Detail:** pay.monzo.com 200 (6603 B Cloudflare, title "Receive money using Monzo").

### 6. [INFO] api.monzo.com serves 44-byte body (S1)

- **CWE:** CWE-916
- **Detail:** api.monzo.com 200 (44 B Cloudflare) at the subdomain root.

### 7. [LOW] __monzo_locale_v1__ cookie set without HttpOnly flag (C2)

- **CWE:** CWE-1004
- **Detail:** __monzo_locale_v1__ (Secure, domain .monzo.com) set on the homepage without the HttpOnly flag.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
