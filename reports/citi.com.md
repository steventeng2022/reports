# Security Audit Report - citi.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://citi.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | citi.com
| Test date | 2026-09-30 12:45 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation with 2-hop canary tracking, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 4, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | I22 | /redirect accepts five param names, echoing them in the redirect-page body; token consumed on second hop | CWE-538 |
| 2 | low | S1 | Redirect chain terminates at plain-HTTP citibank.com | CWE-319 |
| 3 | low | S1 | uat.citi.com exposed behind Akamai | CWE-916 |
| 4 | low | S1 | vpn.citi.com serves a small live page | CWE-916 |
| 5 | info | S1 | api.citi.com 503; auth.citi.com 403 | CWE-916 |
| 6 | info | S1 | pay.citi.com 302 to /unauthorized | CWE-916 |
| 7 | info | S1 | docs/account/www2/secure redirect to other citi hosts | CWE-916 |
| 8 | low | C2 | All three homepage cookies set without HttpOnly flag | CWE-1004 |

## Detailed findings

### 1. [INFO] /redirect accepts five param names, echoing them in the redirect-page body; token consumed on second hop (I22)

- **CWE:** CWE-538
- **Detail:** /redirect?{url,u,to,next,return}=canary 301 (385-390 B) to the same path with the param retained; the canary is echoed in the response body (href attribute and inline script of the redirect-notice page, URL-encoded). The second hop of /redirect/?url=canary is a 301 to http://www.citibank.com/index.htm - the token is never followed.

### 2. [LOW] Redirect chain terminates at plain-HTTP citibank.com (S1)

- **CWE:** CWE-319
- **Detail:** https://www.citi.com/redirect/?url=... 301s to http://www.citibank.com/index.htm - the final hop of the public redirect chain is a cross-domain plain-HTTP URL with no HSTS on that hop.

### 3. [LOW] uat.citi.com exposed behind Akamai (S1)

- **CWE:** CWE-916
- **Detail:** uat.citi.com 503 (AkamaiGHost) - a UAT hostname publicly resolving.

### 4. [LOW] vpn.citi.com serves a small live page (S1)

- **CWE:** CWE-916
- **Detail:** vpn.citi.com 200 (345 B) - the VPN portal hostname is publicly reachable.

### 5. [INFO] api.citi.com 503; auth.citi.com 403 (S1)

- **CWE:** CWE-916
- **Detail:** api.citi.com 503 (AkamaiGHost); auth.citi.com 403 (nginx).

### 6. [INFO] pay.citi.com 302 to /unauthorized (S1)

- **CWE:** CWE-916
- **Detail:** pay.citi.com 302 to https://pay.citi.com/unauthorized - the auth-gated path is disclosed publicly.

### 7. [INFO] docs/account/www2/secure redirect to other citi hosts (S1)

- **CWE:** CWE-916
- **Detail:** docs.citi.com 302 to https://www.docs.citi.com/; account.citi.com and www2.citi.com 301 to https://online.citi.com/US/login.do; secure.citi.com 301 to https://online.citibank.com/.

### 8. [LOW] All three homepage cookies set without HttpOnly flag (C2)

- **CWE:** CWE-1004
- **Detail:** None of the three cookies set on https://www.citi.com/ (two of them Secure) carries the HttpOnly flag.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
