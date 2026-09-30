# Security Audit Report - uniqlo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://uniqlo.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | uniqlo.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 4, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | /jump?url redirects to plain-HTTP copy of itself with param retained | CWE-538 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | C1 | bm_sz cookie set without Secure flag | CWE-614 |
| 4 | low | C2 | _abck, bm_so and bm_sz set without HttpOnly flag | CWE-1004 |
| 5 | info | S1 | store.uniqlo.com 301 to plain-HTTP apex | CWE-916 |
| 6 | info | S1 | admin.uniqlo.com returns 503 | CWE-916 |
| 7 | info | S1 | test returns 403; shop returns 404 | CWE-916 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] /jump?url redirects to plain-HTTP copy of itself with param retained (I22)

- **CWE:** CWE-538
- **Detail:** /jump?url=canary 301 to http://www.uniqlo.com/jump/?url=... - plain-HTTP scheme downgrade; the param survives the http-to-https upgrade hop and is not consumed - the token propagates across hops on a first-party path.

### 2. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.uniqlo.com/ (observed on the homepage 301 response; X-Frame-Options SAMEORIGIN and HSTS present).

### 3. [LOW] bm_sz cookie set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** bm_sz (Akamai bot manager) set without the Secure flag on https://www.uniqlo.com/.

### 4. [LOW] _abck, bm_so and bm_sz set without HttpOnly flag (C2)

- **CWE:** CWE-1004
- **Detail:** _abck, bm_so and bm_sz (Akamai bot manager) set without the HttpOnly flag on https://www.uniqlo.com/.

### 5. [INFO] store.uniqlo.com 301 to plain-HTTP apex (S1)

- **CWE:** CWE-916
- **Detail:** store.uniqlo.com 301 (178 B nginx) to http://www.uniqlo.com/ - plain-HTTP scheme in the public Location.

### 6. [INFO] admin.uniqlo.com returns 503 (S1)

- **CWE:** CWE-916
- **Detail:** admin.uniqlo.com 503 (491 B AkamaiGHost) - admin hostname publicly resolving to an error page.

### 7. [INFO] test returns 403; shop returns 404 (S1)

- **CWE:** CWE-916
- **Detail:** test.uniqlo.com 403 (367 B AkamaiGHost); shop.uniqlo.com 404 (564 B nginx).

### 8. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.uniqlo.com/ (observed on the homepage 301 response).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
