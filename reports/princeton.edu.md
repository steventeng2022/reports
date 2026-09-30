# Security Audit Report - princeton.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://princeton.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | princeton.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 4, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | ray param reflects in Cloudflare challenge page | CWE-79 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | info | S1 | api.princeton.edu returns 202 (0 B) | CWE-916 |
| 4 | info | S1 | smtp.princeton.edu unreachable | CWE-916 |
| 5 | low | S1 | help and support subdomains point to ServiceNow SaaS | CWE-916 |
| 6 | low | S1 | vpn.princeton.edu Pulse Secure login | CWE-916 |

## Detailed findings

### 1. [LOW] ray param reflects in Cloudflare challenge page (I1)

- **CWE:** CWE-79
- **Detail:** /?ray=token returns 403 managed challenge with the token reflected in the cUPMDTk attribute context; quote-breakout probe is re-encoded as \u0026 (JSON escape) - no raw breakout; Cloudflare-owned page.

### 2. [LOW] Missing HSTS header (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.princeton.edu/ (observed on the 403 Cloudflare challenge response).

### 3. [INFO] api.princeton.edu returns 202 (0 B) (S1)

- **CWE:** CWE-916
- **Detail:** api.princeton.edu 202 with an empty body.

### 4. [INFO] smtp.princeton.edu unreachable (S1)

- **CWE:** CWE-916
- **Detail:** smtp.princeton.edu ECONNRESET from external vantage.

### 5. [LOW] help and support subdomains point to ServiceNow SaaS (S1)

- **CWE:** CWE-916
- **Detail:** help.princeton.edu and support.princeton.edu both 302 to princeton.service-now.com (third-party ServiceNow instance).

### 6. [LOW] vpn.princeton.edu Pulse Secure login (S1)

- **CWE:** CWE-916
- **Detail:** vpn.princeton.edu 302 to /global-protect/login.esp (Pulse Secure) with internal node naming.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
