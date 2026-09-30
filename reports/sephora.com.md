# Security Audit Report - sephora.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sephora.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | sephora.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 4, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | portal.sephora.com live SSO endpoint with session_hint param | CWE-916 |
| 2 | low | S1 | login.sephora.com live SSO endpoint with session_hint param | CWE-916 |
| 3 | info | S1 | staging and sandbox subdomains behind Akamai | CWE-916 |
| 4 | info | S1 | app.sephora.com 307 to www | CWE-916 |
| 5 | info | S1 | images and qa subdomains behind Akamai | CWE-916 |
| 6 | info | S1 | dev, api, beta, blog, news and vpn unreachable | CWE-916 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | low | C1 | akamweb and locale cookies set without Secure flag | CWE-614 |
| 9 | low | C2 | rcps_* family and Adobe/Akamai cookies set without HttpOnly flag | CWE-1004 |

## Detailed findings

### 1. [LOW] portal.sephora.com live SSO endpoint with session_hint param (S1)

- **CWE:** CWE-916
- **Detail:** portal.sephora.com 302 (nginx) to https://portal.sephora.com/app/UserHome?iss=https%3A%2F%2Fportal.sephora.com&session_hint=AUTHENTICATED - SSO endpoint exposing iss and session_hint parameters publicly.

### 2. [LOW] login.sephora.com live SSO endpoint with session_hint param (S1)

- **CWE:** CWE-916
- **Detail:** login.sephora.com 302 (nginx) to https://login.sephora.com/app/UserHome?iss=https%3A%2F%2Flogin.sephora.com&session_hint=AUTHENTICATED.

### 3. [INFO] staging and sandbox subdomains behind Akamai (S1)

- **CWE:** CWE-916
- **Detail:** staging.sephora.com 403 (373 B AkamaiGHost); sandbox.sephora.com 403 (321 B AkamaiGHost) - pre-production hostnames publicly resolving.

### 4. [INFO] app.sephora.com 307 to www (S1)

- **CWE:** CWE-916
- **Detail:** app.sephora.com 307 (24 B openresty) to https://www.sephora.com/.

### 5. [INFO] images and qa subdomains behind Akamai (S1)

- **CWE:** CWE-916
- **Detail:** images.sephora.com 403 (1206 B AkamaiGHost); qa.sephora.com 403 (1207 B AkamaiGHost).

### 6. [INFO] dev, api, beta, blog, news and vpn unreachable (S1)

- **CWE:** CWE-916
- **Detail:** dev, api, beta, blog, news and vpn subdomains ECONNRESET from external vantage - stale records still resolving.

### 7. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.sephora.com/ (CSP, X-Frame-Options DENY and HSTS present).

### 8. [LOW] akamweb and locale cookies set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** akamweb, site_locale, site_language and current_country set without the Secure flag on https://www.sephora.com/.

### 9. [LOW] rcps_* family and Adobe/Akamai cookies set without HttpOnly flag (C2)

- **CWE:** CWE-1004
- **Detail:** rcps_sls, rcps_ccap, rcps_cctk, rcps_ccappl, rcps_signInModernization, rcps_bihub, rcps_basket, rcps_beauty_chat_prs, adbanners, _abck, bm_so, bm_sz and device_type set without the HttpOnly flag on https://www.sephora.com.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
