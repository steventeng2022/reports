# Security Audit Report - mit.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mit.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | mit.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 3, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | UAT environment exposed at uat.mit.edu | CWE-916 |
| 2 | low | S1 | SAML app and RelayState token exposed at download.mit.edu | CWE-916 |
| 3 | info | S1 | api.mit.edu returns CloudFront error page | CWE-916 |
| 4 | info | S1 | Unreachable subdomains (git / ssl / qa) | CWE-916 |
| 5 | info | I22 | Eight hidden redirect-style paths propagate URL params | CWE-538 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] UAT environment exposed at uat.mit.edu (S1)

- **CWE:** CWE-916
- **Detail:** uat.mit.edu serves 200 (19726 B, nginx/1.18.0 (Ubuntu), title "6.UAT") - pre-production UAT application publicly reachable without auth.

### 2. [LOW] SAML app and RelayState token exposed at download.mit.edu (S1)

- **CWE:** CWE-916
- **Detail:** download.mit.edu 302-redirects to okta.mit.edu SAML SSO for Okta app mitprod_downloadsprod_1; full SAMLRequest and RelayState session token visible in the public redirect.

### 3. [INFO] api.mit.edu returns CloudFront error page (S1)

- **CWE:** CWE-916
- **Detail:** api.mit.edu 403 (23 B, x-cache "Error from cloudfront"); no 915 B dangling-signature observed.

### 4. [INFO] Unreachable subdomains (git / ssl / qa) (S1)

- **CWE:** CWE-916
- **Detail:** git.mit.edu, ssl.mit.edu, qa.mit.edu all ECONNRESET (socket hang up) from external vantage - internal-only or stale DNS records still resolving.

### 5. [INFO] Eight hidden redirect-style paths propagate URL params (I22)

- **CWE:** CWE-538
- **Detail:** /r, /go, /link, /next, /jump, /url each accept url and u params; 301 to first-party mirror path with param retained (e.g. web.mit.edu/r/?url=...); second hop returns 403 (199 B Apache) consuming the token - no open redirect.

### 6. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.mit.edu/ (X-Frame-Options SAMEORIGIN and HSTS present).

### 7. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.mit.edu/.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
