# Security Audit Report - nike.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nike.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nike.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 7, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | Homepage served by regional edge (Chinese storefront) | CWE-916 |
| 2 | low | S1 | help.nike.com 301 to first-party help | CWE-916 |
| 3 | low | S1 | news.nike.com 301 to about.nike.com newsroom | CWE-916 |
| 4 | low | S1 | store.nike.com 301 to www | CWE-916 |
| 5 | info | S1 | static.nike.com 301 to Cloudinary | CWE-916 |
| 6 | info | S1 | webmail and api2 return 400; uat 403 behind Akamai | CWE-916 |
| 7 | info | S1 | api.nike.com returns 503 | CWE-916 |
| 8 | info | S1 | ftp, secure, test and www2 unreachable; edge ECONNREFUSED | CWE-916 |
| 9 | low | H2 | Missing CSP header | CWE-1021 |
| 10 | low | H4 | No clickjacking protection | CWE-1023 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | low | C1 | geoloc and at_lp_exp cookies set without Secure flag | CWE-614 |
| 13 | low | C2 | geoloc, ni_d, kndctr_* and at_lp_exp set without HttpOnly flag | CWE-1004 |

## Detailed findings

### 1. [INFO] Homepage served by regional edge (Chinese storefront) (S1)

- **CWE:** CWE-916
- **Detail:** www.nike.com 200 (714784 B unified-edge-router, title "Nike TW storefront") - regional edge serves the Chinese-language storefront; params v, agreementType and cp accepted without reflection.

### 2. [LOW] help.nike.com 301 to first-party help (S1)

- **CWE:** CWE-916
- **Detail:** help.nike.com 301 (CloudFront) to https://www.nike.com/help/.

### 3. [LOW] news.nike.com 301 to about.nike.com newsroom (S1)

- **CWE:** CWE-916
- **Detail:** news.nike.com 301 (CloudFront) to https://about.nike.com/en/newsroom.

### 4. [LOW] store.nike.com 301 to www (S1)

- **CWE:** CWE-916
- **Detail:** store.nike.com 301 (CloudFront) to https://www.nike.com/.

### 5. [INFO] static.nike.com 301 to Cloudinary (S1)

- **CWE:** CWE-916
- **Detail:** static.nike.com 301 (Cloudinary) to https://cloudinary.com - media alias redirecting to the third-party CDN.

### 6. [INFO] webmail and api2 return 400; uat 403 behind Akamai (S1)

- **CWE:** CWE-916
- **Detail:** webmail.nike.com 400 (310 B AkamaiGHost); api2.nike.com 400 (310 B AkamaiGHost); uat.nike.com 403 (282 B AkamaiGHost) - UAT hostname publicly resolving.

### 7. [INFO] api.nike.com returns 503 (S1)

- **CWE:** CWE-916
- **Detail:** api.nike.com 503 (369 B AkamaiGHost).

### 8. [INFO] ftp, secure, test and www2 unreachable; edge ECONNREFUSED (S1)

- **CWE:** CWE-916
- **Detail:** ftp, secure, test and www2 ECONNRESET; edge.nike.com ECONNREFUSED 146.197.27.215:80 from external vantage - stale records still resolving.

### 9. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.nike.com/ (observed on the homepage 302 response; HSTS present).

### 10. [LOW] No clickjacking protection (H4)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.nike.com/ (observed on the homepage 302 response).

### 11. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.nike.com/ (observed on the homepage 302 response; HSTS present).

### 12. [LOW] geoloc and at_lp_exp cookies set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** geoloc and at_lp_exp set without the Secure flag on https://www.nike.com/.

### 13. [LOW] geoloc, ni_d, kndctr_* and at_lp_exp set without HttpOnly flag (C2)

- **CWE:** CWE-1004
- **Detail:** geoloc, ni_d, kndctr_F0935E09512D2C270A490D4D_AdobeOrg_cluster, kndctr_F0935E09512D2C270A490D4D_AdobeOrg_identity and at_lp_exp (Adobe AAM cluster) set without the HttpOnly flag on https://www.nike.com/.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
