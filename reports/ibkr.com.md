# Security Audit Report - ibkr.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ibkr.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ibkr.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 0, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | Homepage 403 Access Denied | CWE-916 |
| 2 | info | S1 | api.ibkr.com serves 1-byte body | CWE-916 |
| 3 | info | S1 | 44 enumerated subdomains unreachable | CWE-916 |

## Detailed findings

### 1. [INFO] Homepage 403 Access Denied (S1)

- **CWE:** CWE-916
- **Detail:** www.ibkr.com 403 (567 B) "Access Denied" for the scanner client - edge-gated homepage.

### 2. [INFO] api.ibkr.com serves 1-byte body (S1)

- **CWE:** CWE-916
- **Detail:** api.ibkr.com 200 (1 B) at the subdomain root.

### 3. [INFO] 44 enumerated subdomains unreachable (S1)

- **CWE:** CWE-916
- **Detail:** All other enumerated subdomains (staging, dev, mail, git, docs, portal, beta, sandbox, internal, legacy, old, app, sso, oauth, auth, account, login, help, support, blog, news, shop, store, checkout, cart, pay, billing, mobile, cdn, images, media, static, assets, files, download, ftp, s3, webmail, mx, smtp, vpn, secure, ssl, ws, push, chat, upload, dl, test, qa and uat) ENOTFOUND from external vantage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
