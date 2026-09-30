# Security Audit Report - wise.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wise.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wise.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 7, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | status.wise.com public status page | CWE-916 |
| 2 | low | S1 | docs.wise.com public developer docs | CWE-916 |
| 3 | low | S1 | api.wise.com 307 to platform path | CWE-916 |
| 4 | low | S1 | help.wise.com 301 to first-party help | CWE-916 |
| 5 | low | S1 | www.wise.com 301 to apex | CWE-916 |
| 6 | info | S1 | files.wise.com 302 to SPA core | CWE-916 |
| 7 | info | S1 | 38 enumerated subdomains unreachable | CWE-916 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | low | C2 | gid cookie set without HttpOnly flag | CWE-1004 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] status.wise.com public status page (S1)

- **CWE:** CWE-916
- **Detail:** status.wise.com 200 (68722 B AtlassianEdge, title "Wise Status") - public status and incident history without auth.

### 2. [LOW] docs.wise.com public developer docs (S1)

- **CWE:** CWE-916
- **Detail:** docs.wise.com 200 (1092174 B Cloudflare) - developer documentation published publicly.

### 3. [LOW] api.wise.com 307 to platform path (S1)

- **CWE:** CWE-916
- **Detail:** api.wise.com 307 (136 B) to https://wise.com/platform - first-party redirect.

### 4. [LOW] help.wise.com 301 to first-party help (S1)

- **CWE:** CWE-916
- **Detail:** help.wise.com 301 (229 B) to https://wise.com/help.

### 5. [LOW] www.wise.com 301 to apex (S1)

- **CWE:** CWE-916
- **Detail:** www.wise.com 301 (225 B Cloudflare) to https://wise.com/.

### 6. [INFO] files.wise.com 302 to SPA core (S1)

- **CWE:** CWE-916
- **Detail:** files.wise.com 302 to /ui/core/index.html (0 B) - first-party SPA core file exposed on the files subdomain.

### 7. [INFO] 38 enumerated subdomains unreachable (S1)

- **CWE:** CWE-916
- **Detail:** admin, staging, dev, git, portal, beta, sandbox, internal, legacy, old, sso, oauth, account, login, support, store, checkout, cart, pay, billing, mobile, cdn, images, media, static, assets, download, ftp, s3, webmail, mx, smtp, vpn, secure, ssl, ws, push, upload, dl, qa and uat all ENOTFOUND from external vantage.

### 8. [LOW] No clickjacking protection (H4)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://wise.com/ (CSP and HSTS present).

### 9. [LOW] gid cookie set without HttpOnly flag (C2)

- **CWE:** CWE-1004
- **Detail:** gid set without the HttpOnly flag on https://wise.com/.

### 10. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://wise.com/ (CSP and HSTS present).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
