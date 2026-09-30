# Security Audit Report - capitalone.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://capitalone.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | capitalone.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 3, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | I22 | 20 redirect-style paths 301-redirect with params retained | CWE-538 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | C1 | TLTUID cookie set without Secure flag | CWE-614 |
| 4 | info | S1 | api.capitalone.com returns 404 | CWE-916 |
| 5 | low | S1 | mail.capitalone.com first-party mail | CWE-916 |
| 6 | info | S1 | mobile.capitalone.com returns 404 (76 B CloudFront) | CWE-916 |
| 7 | info | S1 | chat.capitalone.com returns 400 (11 B CloudFront) | CWE-916 |

## Detailed findings

### 1. [INFO] 20 redirect-style paths 301-redirect with params retained (I22)

- **CWE:** CWE-538
- **Detail:** /redirect, /r, /go, /out, /link, /continue, /next, /return, /redir, /jump, /url, /target, /callback, /follow accept url/u/to/next/return; 301 to the same absolute path with the param retained; second hop is a 404 (100 B AkamaiNetStorage) consuming the token - no open redirect.

### 2. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.capitalone.com/ (X-Frame-Options SAMEORIGIN, HSTS and Referrer-Policy present).

### 3. [LOW] TLTUID cookie set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** TLTUID (expiry 2031, domain .capitalone.com) set without the Secure flag.

### 4. [INFO] api.capitalone.com returns 404 (S1)

- **CWE:** CWE-916
- **Detail:** api.capitalone.com 404 (115 B).

### 5. [LOW] mail.capitalone.com first-party mail (S1)

- **CWE:** CWE-916
- **Detail:** mail.capitalone.com 301 (Microsoft-HTTPAPI/2.0) to /mail/ first-party mail app.

### 6. [INFO] mobile.capitalone.com returns 404 (76 B CloudFront) (S1)

- **CWE:** CWE-916
- **Detail:** mobile.capitalone.com 404 with a CloudFront body.

### 7. [INFO] chat.capitalone.com returns 400 (11 B CloudFront) (S1)

- **CWE:** CWE-916
- **Detail:** chat.capitalone.com 400 (11 B).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
