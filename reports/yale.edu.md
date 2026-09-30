# Security Audit Report - yale.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yale.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | yale.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 3 | low | S1 | auth.yale.edu Shibboleth IdP | CWE-916 |
| 4 | low | S1 | mobile.yale.edu cross-department redirect | CWE-916 |
| 5 | low | S1 | webmail.yale.edu 301 to HTTP location | CWE-916 |
| 6 | info | S1 | vpn.yale.edu points to internal node | CWE-916 |
| 7 | info | S1 | Unreachable subdomains (mail / proxy) | CWE-916 |

## Detailed findings

### 1. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.yale.edu/ (X-Frame-Options SAMEORIGIN and HSTS present).

### 2. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.yale.edu/.

### 3. [LOW] auth.yale.edu Shibboleth IdP (S1)

- **CWE:** CWE-916
- **Detail:** auth.yale.edu 302 to auth.yale.edu:443/idp/ (Shibboleth identity provider).

### 4. [LOW] mobile.yale.edu cross-department redirect (S1)

- **CWE:** CWE-916
- **Detail:** mobile.yale.edu 301 to medicine.yale.edu/cbds/mobile.aspx - mobile alias redirecting into a different departmental site.

### 5. [LOW] webmail.yale.edu 301 to HTTP location (S1)

- **CWE:** CWE-916
- **Detail:** webmail.yale.edu 301 with Location http://its.yale.edu/services/email-and-calendars/webmail-portal (plain-HTTP scheme in the redirect).

### 6. [INFO] vpn.yale.edu points to internal node (S1)

- **CWE:** CWE-916
- **Detail:** vpn.yale.edu 302 to vpn6.its.yale.edu (numbered internal node name).

### 7. [INFO] Unreachable subdomains (mail / proxy) (S1)

- **CWE:** CWE-916
- **Detail:** mail.yale.edu, proxy.yale.edu ECONNRESET from external vantage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
