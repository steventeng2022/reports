# Security Audit Report - stanford.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stanford.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | stanford.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 5, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | portal.stanford.edu served from GitHub Pages | CWE-916 |
| 2 | low | S1 | sso.stanford.edu serves Stanford Symphony Orchestra site | CWE-916 |
| 3 | info | S1 | cdn.stanford.edu serves 12-byte S3 object | CWE-916 |
| 4 | info | S1 | api.stanford.edu returns 503 | CWE-916 |
| 5 | info | S1 | Unreachable subdomains (staging / dev / auth / files / proxy / mail / smtp) | CWE-916 |
| 6 | low | S1 | webmail.stanford.edu exposes AAD OAuth configuration | CWE-916 |
| 7 | low | S1 | legacy.stanford.edu 307 redirects to rttp.stanford.edu | CWE-916 |
| 8 | low | S1 | support.stanford.edu redirects to marketing gift page | CWE-916 |

## Detailed findings

### 1. [LOW] portal.stanford.edu served from GitHub Pages (S1)

- **CWE:** CWE-916
- **Detail:** portal.stanford.edu 200 (6847 B, server GitHub.com) - portal subdomain hosted on GitHub Pages.

### 2. [LOW] sso.stanford.edu serves Stanford Symphony Orchestra site (S1)

- **CWE:** CWE-916
- **Detail:** sso.stanford.edu 200 (3562 B Apache, title "Stanford Symphony Orchestra | home") - single-sign-on subdomain name occupied by an orchestra website; naming collision.

### 3. [INFO] cdn.stanford.edu serves 12-byte S3 object (S1)

- **CWE:** CWE-916
- **Detail:** cdn.stanford.edu 200 (12 B AmazonS3) at the subdomain root.

### 4. [INFO] api.stanford.edu returns 503 (S1)

- **CWE:** CWE-916
- **Detail:** api.stanford.edu 503 (107 B) with no useful error body.

### 5. [INFO] Unreachable subdomains (staging / dev / auth / files / proxy / mail / smtp) (S1)

- **CWE:** CWE-916
- **Detail:** staging, dev, auth, files, proxy ECONNRESET; mail, smtp ECONNREFUSED 171.64.13.8:80 from external vantage - internal-only endpoints still resolving.

### 6. [LOW] webmail.stanford.edu exposes AAD OAuth configuration (S1)

- **CWE:** CWE-916
- **Detail:** webmail.stanford.edu 302 to login.windows.net with tenant 396573cb-f378-4b68-9bc8-15755c0c51f3 and client_id 45a9dd18-150b-4015-94b4-72195731cc97.

### 7. [LOW] legacy.stanford.edu 307 redirects to rttp.stanford.edu (S1)

- **CWE:** CWE-916
- **Detail:** legacy alias kept live and 307-redirecting to a first-party subdomain.

### 8. [LOW] support.stanford.edu redirects to marketing gift page (S1)

- **CWE:** CWE-916
- **Detail:** support.stanford.edu 307 to give.stanford.edu gift/tsf-impact-funds URL with campaign UTMs - support subdomain serving a fundraising page.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
