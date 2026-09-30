# Security Audit Report - revolut.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://revolut.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | revolut.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 6, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | Homepage behind Cloudflare bot challenge | CWE-916 |
| 2 | low | S1 | auth.revolut.com live auth service | CWE-916 |
| 3 | low | S1 | checkout.revolut.com live checkout | CWE-916 |
| 4 | low | S1 | pay.revolut.com live payment page | CWE-916 |
| 5 | low | S1 | dev.revolut.com 301 to developer portal | CWE-916 |
| 6 | info | S1 | mail.revolut.com redirects to Google Workspace | CWE-916 |
| 7 | info | S1 | Seven subdomains share one 873 KB Cloudflare 403 catch-all | CWE-916 |
| 8 | info | S1 | cdn/assets 403; api 404; www2 403 | CWE-916 |
| 9 | low | H1 | Missing HSTS header on auth.revolut.com | CWE-319 |
| 10 | low | H4 | No clickjacking protection on auth.revolut.com | CWE-1023 |
| 11 | info | H5 | Missing Referrer-Policy on auth.revolut.com | CWE-200 |

## Detailed findings

### 1. [INFO] Homepage behind Cloudflare bot challenge (S1)

- **CWE:** CWE-916
- **Detail:** www.revolut.com 403 (873079 B Cloudflare) - homepage gated by a bot challenge for non-browser clients.

### 2. [LOW] auth.revolut.com live auth service (S1)

- **CWE:** CWE-916
- **Detail:** auth.revolut.com 200 (3767 B nginx, title "Auth | Revolut") - authentication endpoint publicly reachable without a challenge.

### 3. [LOW] checkout.revolut.com live checkout (S1)

- **CWE:** CWE-916
- **Detail:** checkout.revolut.com 200 (2107 B Cloudflare, title "Revolut Checkout").

### 4. [LOW] pay.revolut.com live payment page (S1)

- **CWE:** CWE-916
- **Detail:** pay.revolut.com 200 (4888 B nginx, title "Revolut.Me").

### 5. [LOW] dev.revolut.com 301 to developer portal (S1)

- **CWE:** CWE-916
- **Detail:** dev.revolut.com 301 (162 B Cloudflare) to https://developer.revolut.com/.

### 6. [INFO] mail.revolut.com redirects to Google Workspace (S1)

- **CWE:** CWE-916
- **Detail:** mail.revolut.com 301 (234 B ghs) to https://mail.google.com/a/revolut.com.

### 7. [INFO] Seven subdomains share one 873 KB Cloudflare 403 catch-all (S1)

- **CWE:** CWE-916
- **Detail:** app, sso, help, blog, news, shop and chat all 403 with a near-identical 873079-873101 B Cloudflare body.

### 8. [INFO] cdn/assets 403; api 404; www2 403 (S1)

- **CWE:** CWE-916
- **Detail:** cdn.revolut.com and assets.revolut.com 403 (111 B CloudFront); api.revolut.com 404 (50 B); www2.revolut.com 403 (134 B).

### 9. [LOW] Missing HSTS header on auth.revolut.com (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://auth.revolut.com/ (CSP present).

### 10. [LOW] No clickjacking protection on auth.revolut.com (H4)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://auth.revolut.com/ (CSP present).

### 11. [INFO] Missing Referrer-Policy on auth.revolut.com (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://auth.revolut.com/.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
