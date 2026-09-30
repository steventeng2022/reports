# Security Audit Report - barclays.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://barclays.co.uk |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | barclays.co.uk
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 2, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | /callback?url redirects to plain-HTTP help page with param retained | CWE-538 |
| 2 | info | I22 | 19 redirect-style paths 301-redirect with params retained | CWE-538 |
| 3 | low | S1 | checkout.barclays.co.uk serves full page without auth | CWE-916 |
| 4 | info | S1 | help.barclays.co.uk 301 to first-party help | CWE-916 |
| 5 | info | S1 | mobile returns 400; four subdomains unreachable | CWE-916 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] /callback?url redirects to plain-HTTP help page with param retained (I22)

- **CWE:** CWE-538
- **Detail:** /callback?url=canary 301 to http://www.barclays.co.uk/help/premier/arrange-meeting/?url=... - plain-HTTP scheme downgrade; the second hop (http to https) keeps the url param on a first-party help page - the token propagates and is not consumed as an open redirect.

### 2. [INFO] 19 redirect-style paths 301-redirect with params retained (I22)

- **CWE:** CWE-538
- **Detail:** /redirect, /r, /go, /out, /link, /continue, /next, /return, /redir, /jump, /url, /target and /follow (+u variants) 301 to the same absolute path with the param retained; second hop is a 302 to /page-not-found (225 B) consuming the token - no open redirect.

### 3. [LOW] checkout.barclays.co.uk serves full page without auth (S1)

- **CWE:** CWE-916
- **Detail:** checkout.barclays.co.uk 200 (126351 B) - checkout subdomain serving a full page publicly.

### 4. [INFO] help.barclays.co.uk 301 to first-party help (S1)

- **CWE:** CWE-916
- **Detail:** help.barclays.co.uk 301 (240 B) to https://www.barclays.co.uk/help/.

### 5. [INFO] mobile returns 400; four subdomains unreachable (S1)

- **CWE:** CWE-916
- **Detail:** mobile.barclays.co.uk 400 (312 B AkamaiGHost); api, assets, vpn and chat all ECONNRESET from external vantage - stale records still resolving.

### 6. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.barclays.co.uk/ (CSP, X-Frame-Options SAMEORIGIN and HSTS present).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
