# Security Audit Report - duke.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://duke.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | duke.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 6, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | low | S1 | mail.duke.edu redirects to Office 365 OWA | CWE-916 |
| 6 | low | S1 | portal.duke.edu exposes internal node name | CWE-916 |
| 7 | low | S1 | news.duke.edu first-party news site | CWE-916 |
| 8 | info | S1 | smtp.duke.edu unreachable | CWE-916 |

## Detailed findings

### 1. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.duke.edu/.

### 2. [LOW] No clickjacking protection (H4)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.duke.edu/.

### 3. [LOW] Missing HSTS header (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.duke.edu/.

### 4. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.duke.edu/.

### 5. [LOW] mail.duke.edu redirects to Office 365 OWA (S1)

- **CWE:** CWE-916
- **Detail:** mail.duke.edu 301 to outlook.office365.com/owa/duke.edu (first-party tenant).

### 6. [LOW] portal.duke.edu exposes internal node name (S1)

- **CWE:** CWE-916
- **Detail:** portal.duke.edu and vpn.duke.edu 302 to portal-02.duke.edu - internal numbered node hostname exposed in public Location.

### 7. [LOW] news.duke.edu first-party news site (S1)

- **CWE:** CWE-916
- **Detail:** news.duke.edu 200 (48331 B Apache).

### 8. [INFO] smtp.duke.edu unreachable (S1)

- **CWE:** CWE-916
- **Detail:** smtp.duke.edu ECONNRESET from external vantage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
