# Security Audit Report - figma.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://figma.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | figma.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 3, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | I22 | 14 redirect-style paths 308-redirect to trailing-slash variants with params retained | CWE-538 |
| 2 | low | S1 | admin.figma.com exposes Cognito OAuth configuration | CWE-916 |
| 3 | info | S1 | staging.figma.com returns 202 (2011 B CloudFront) | CWE-916 |
| 4 | info | S1 | cdn and static subdomains return S3 error pages | CWE-916 |
| 5 | low | S1 | store.figma.com first-party store | CWE-916 |
| 6 | low | S1 | status.figma.com public status page | CWE-916 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [INFO] 14 redirect-style paths 308-redirect to trailing-slash variants with params retained (I22)

- **CWE:** CWE-538
- **Detail:** /redirect, /r, /go, /out, /link, /continue, /next, /return, /redir, /jump, /url, /target, /callback, /follow accept url/u/to/next/return; 308 to the same path with a trailing slash and the param retained; second hop is a 404 (1.3 MB SPA) consuming the token - no open redirect.

### 2. [LOW] admin.figma.com exposes Cognito OAuth configuration (S1)

- **CWE:** CWE-916
- **Detail:** admin.figma.com 302 to figma-production-admin.auth.us-west-2.amazoncognito.com (client_id 2lsagdo9asi3ehjvtslcrsqp24, redirect to /oauth2/idpresponse).

### 3. [INFO] staging.figma.com returns 202 (2011 B CloudFront) (S1)

- **CWE:** CWE-916
- **Detail:** staging.figma.com 202 with a CloudFront challenge/error body - staging host live on the public CDN.

### 4. [INFO] cdn and static subdomains return S3 error pages (S1)

- **CWE:** CWE-916
- **Detail:** cdn.figma.com 403 (263 B) and static.figma.com 403 (243 B) AmazonS3 "Error from cloudfront".

### 5. [LOW] store.figma.com first-party store (S1)

- **CWE:** CWE-916
- **Detail:** store.figma.com 200 (420149 B Cloudflare).

### 6. [LOW] status.figma.com public status page (S1)

- **CWE:** CWE-916
- **Detail:** status.figma.com 200 (86026 B AtlassianEdge) - public status page exposing incident history.

### 7. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.figma.com/ (CSP, X-Frame-Options SAMEORIGIN and HSTS present).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
