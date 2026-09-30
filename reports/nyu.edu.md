# Security Audit Report - nyu.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nyu.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nyu.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 4, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | I22 | 20 redirect-style paths append challenge UUID and retain params | CWE-538 |
| 2 | low | S1 | sso.nyu.edu serves Shibboleth metadata (Jetty) | CWE-916 |
| 3 | low | S1 | docs.nyu.edu redirects to Google Drive | CWE-916 |
| 4 | low | S1 | mail.nyu.edu redirects to Google Workspace | CWE-916 |
| 5 | info | S1 | beta.nyu.edu returns 403 (3064 B CloudFront) | CWE-916 |
| 6 | info | S1 | mobile.nyu.edu returns 404 (0 B awselb) | CWE-916 |
| 7 | info | S1 | Unreachable subdomains (login / mx / smtp / proxy) | CWE-916 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [INFO] 20 redirect-style paths append challenge UUID and retain params (I22)

- **CWE:** CWE-538
- **Detail:** /redirect, /r, /go, /out, /link, /continue, /next, /return, /redir, /jump, /url, /target, /callback, /follow each accept url/u/to/next/return; 302 to the same path with challenge=<UUID> appended and the original param retained; second hop is a 202 CloudFront bot challenge (token not publicly consumed) - no open redirect.

### 2. [LOW] sso.nyu.edu serves Shibboleth metadata (Jetty) (S1)

- **CWE:** CWE-916
- **Detail:** sso.nyu.edu 200 (694 B Jetty(12.0.19), "NYU Shibboleth Metadata").

### 3. [LOW] docs.nyu.edu redirects to Google Drive (S1)

- **CWE:** CWE-916
- **Detail:** docs.nyu.edu 302 (CloudFront Lambda) to drive.google.com/a/nyu.edu.

### 4. [LOW] mail.nyu.edu redirects to Google Workspace (S1)

- **CWE:** CWE-916
- **Detail:** mail.nyu.edu 301 to mail.google.com/a/nyu.edu.

### 5. [INFO] beta.nyu.edu returns 403 (3064 B CloudFront) (S1)

- **CWE:** CWE-916
- **Detail:** beta.nyu.edu 403 with a CloudFront error page.

### 6. [INFO] mobile.nyu.edu returns 404 (0 B awselb) (S1)

- **CWE:** CWE-916
- **Detail:** mobile.nyu.edu 404 with an empty AWS ELB body.

### 7. [INFO] Unreachable subdomains (login / mx / smtp / proxy) (S1)

- **CWE:** CWE-916
- **Detail:** login, mx, smtp, proxy all ECONNRESET from external vantage.

### 8. [LOW] No clickjacking protection (H4)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.nyu.edu/ (CSP and HSTS present).

### 9. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.nyu.edu/.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
