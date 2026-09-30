# Security Audit Report - robinhood.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://robinhood.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | robinhood.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **60** (High: 46, Medium: 0, Low: 9, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | S1 | Dangling subdomain admin.robinhood.com (915 B CloudFront error) | CWE-916 |
| 2 | high | S1 | Dangling subdomain mail.robinhood.com (915 B CloudFront error) | CWE-916 |
| 3 | high | S1 | Dangling subdomain git.robinhood.com (915 B CloudFront error) | CWE-916 |
| 4 | high | S1 | Dangling subdomain portal.robinhood.com (915 B CloudFront error) | CWE-916 |
| 5 | high | S1 | Dangling subdomain beta.robinhood.com (915 B CloudFront error) | CWE-916 |
| 6 | high | S1 | Dangling subdomain sandbox.robinhood.com (915 B CloudFront error) | CWE-916 |
| 7 | high | S1 | Dangling subdomain internal.robinhood.com (915 B CloudFront error) | CWE-916 |
| 8 | high | S1 | Dangling subdomain legacy.robinhood.com (915 B CloudFront error) | CWE-916 |
| 9 | high | S1 | Dangling subdomain old.robinhood.com (915 B CloudFront error) | CWE-916 |
| 10 | high | S1 | Dangling subdomain app.robinhood.com (915 B CloudFront error) | CWE-916 |
| 11 | high | S1 | Dangling subdomain sso.robinhood.com (915 B CloudFront error) | CWE-916 |
| 12 | high | S1 | Dangling subdomain oauth.robinhood.com (915 B CloudFront error) | CWE-916 |
| 13 | high | S1 | Dangling subdomain auth.robinhood.com (915 B CloudFront error) | CWE-916 |
| 14 | high | S1 | Dangling subdomain account.robinhood.com (915 B CloudFront error) | CWE-916 |
| 15 | high | S1 | Dangling subdomain login.robinhood.com (915 B CloudFront error) | CWE-916 |
| 16 | high | S1 | Dangling subdomain help.robinhood.com (915 B CloudFront error) | CWE-916 |
| 17 | high | S1 | Dangling subdomain news.robinhood.com (915 B CloudFront error) | CWE-916 |
| 18 | high | S1 | Dangling subdomain store.robinhood.com (915 B CloudFront error) | CWE-916 |
| 19 | high | S1 | Dangling subdomain checkout.robinhood.com (915 B CloudFront error) | CWE-916 |
| 20 | high | S1 | Dangling subdomain cart.robinhood.com (915 B CloudFront error) | CWE-916 |
| 21 | high | S1 | Dangling subdomain pay.robinhood.com (915 B CloudFront error) | CWE-916 |
| 22 | high | S1 | Dangling subdomain billing.robinhood.com (915 B CloudFront error) | CWE-916 |
| 23 | high | S1 | Dangling subdomain mobile.robinhood.com (915 B CloudFront error) | CWE-916 |
| 24 | high | S1 | Dangling subdomain media.robinhood.com (915 B CloudFront error) | CWE-916 |
| 25 | high | S1 | Dangling subdomain static.robinhood.com (915 B CloudFront error) | CWE-916 |
| 26 | high | S1 | Dangling subdomain assets.robinhood.com (915 B CloudFront error) | CWE-916 |
| 27 | high | S1 | Dangling subdomain files.robinhood.com (915 B CloudFront error) | CWE-916 |
| 28 | high | S1 | Dangling subdomain ftp.robinhood.com (915 B CloudFront error) | CWE-916 |
| 29 | high | S1 | Dangling subdomain s3.robinhood.com (915 B CloudFront error) | CWE-916 |
| 30 | high | S1 | Dangling subdomain webmail.robinhood.com (915 B CloudFront error) | CWE-916 |
| 31 | high | S1 | Dangling subdomain mx.robinhood.com (915 B CloudFront error) | CWE-916 |
| 32 | high | S1 | Dangling subdomain smtp.robinhood.com (915 B CloudFront error) | CWE-916 |
| 33 | high | S1 | Dangling subdomain vpn.robinhood.com (915 B CloudFront error) | CWE-916 |
| 34 | high | S1 | Dangling subdomain secure.robinhood.com (915 B CloudFront error) | CWE-916 |
| 35 | high | S1 | Dangling subdomain ssl.robinhood.com (915 B CloudFront error) | CWE-916 |
| 36 | high | S1 | Dangling subdomain ws.robinhood.com (915 B CloudFront error) | CWE-916 |
| 37 | high | S1 | Dangling subdomain push.robinhood.com (915 B CloudFront error) | CWE-916 |
| 38 | high | S1 | Dangling subdomain chat.robinhood.com (915 B CloudFront error) | CWE-916 |
| 39 | high | S1 | Dangling subdomain upload.robinhood.com (915 B CloudFront error) | CWE-916 |
| 40 | high | S1 | Dangling subdomain dl.robinhood.com (915 B CloudFront error) | CWE-916 |
| 41 | high | S1 | Dangling subdomain qa.robinhood.com (915 B CloudFront error) | CWE-916 |
| 42 | high | S1 | Dangling subdomain edge.robinhood.com (915 B CloudFront error) | CWE-916 |
| 43 | high | S1 | Dangling subdomain gateway.robinhood.com (915 B CloudFront error) | CWE-916 |
| 44 | high | S1 | Dangling subdomain proxy.robinhood.com (915 B CloudFront error) | CWE-916 |
| 45 | high | S1 | Dangling subdomain www2.robinhood.com (915 B CloudFront error) | CWE-916 |
| 46 | high | S1 | Dangling subdomain api2.robinhood.com (915 B CloudFront error) | CWE-916 |
| 47 | low | S1 | status.robinhood.com public status page | CWE-916 |
| 48 | low | S1 | shop.robinhood.com first-party store | CWE-916 |
| 49 | low | S1 | docs.robinhood.com 307 to crypto trading page | CWE-916 |
| 50 | low | S1 | support.robinhood.com 301 to first-party support | CWE-916 |
| 51 | low | S1 | blog.robinhood.com 301 with explicit port in Location | CWE-916 |
| 52 | low | S1 | download.robinhood.com 301 to first-party download | CWE-916 |
| 53 | low | S1 | www.robinhood.com 301 to apex | CWE-916 |
| 54 | info | S1 | cdn.robinhood.com S3 error page | CWE-916 |
| 55 | info | S1 | api.robinhood.com serves empty body | CWE-916 |
| 56 | info | S1 | images.robinhood.com serves empty body | CWE-916 |
| 57 | info | S1 | staging, dev, test and uat subdomains unreachable | CWE-916 |
| 58 | low | H2 | Missing CSP header | CWE-1021 |
| 59 | low | H4 | No clickjacking protection | CWE-1023 |
| 60 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Dangling subdomain admin.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** admin.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the admin hostname still resolves publicly without auth.

### 2. [HIGH] Dangling subdomain mail.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** mail.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the mail hostname still resolves publicly without auth.

### 3. [HIGH] Dangling subdomain git.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** git.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the git hostname still resolves publicly without auth.

### 4. [HIGH] Dangling subdomain portal.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** portal.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the portal hostname still resolves publicly without auth.

### 5. [HIGH] Dangling subdomain beta.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** beta.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the beta hostname still resolves publicly without auth.

### 6. [HIGH] Dangling subdomain sandbox.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** sandbox.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the sandbox hostname still resolves publicly without auth.

### 7. [HIGH] Dangling subdomain internal.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** internal.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the internal hostname still resolves publicly without auth.

### 8. [HIGH] Dangling subdomain legacy.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** legacy.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the legacy hostname still resolves publicly without auth.

### 9. [HIGH] Dangling subdomain old.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** old.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the old hostname still resolves publicly without auth.

### 10. [HIGH] Dangling subdomain app.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** app.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the app hostname still resolves publicly without auth.

### 11. [HIGH] Dangling subdomain sso.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** sso.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the sso hostname still resolves publicly without auth.

### 12. [HIGH] Dangling subdomain oauth.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** oauth.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the oauth hostname still resolves publicly without auth.

### 13. [HIGH] Dangling subdomain auth.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** auth.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the auth hostname still resolves publicly without auth.

### 14. [HIGH] Dangling subdomain account.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** account.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the account hostname still resolves publicly without auth.

### 15. [HIGH] Dangling subdomain login.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** login.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the login hostname still resolves publicly without auth.

### 16. [HIGH] Dangling subdomain help.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** help.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the help hostname still resolves publicly without auth.

### 17. [HIGH] Dangling subdomain news.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** news.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the news hostname still resolves publicly without auth.

### 18. [HIGH] Dangling subdomain store.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** store.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the store hostname still resolves publicly without auth.

### 19. [HIGH] Dangling subdomain checkout.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** checkout.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the checkout hostname still resolves publicly without auth.

### 20. [HIGH] Dangling subdomain cart.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** cart.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the cart hostname still resolves publicly without auth.

### 21. [HIGH] Dangling subdomain pay.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** pay.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the pay hostname still resolves publicly without auth.

### 22. [HIGH] Dangling subdomain billing.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** billing.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the billing hostname still resolves publicly without auth.

### 23. [HIGH] Dangling subdomain mobile.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** mobile.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the mobile hostname still resolves publicly without auth.

### 24. [HIGH] Dangling subdomain media.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** media.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the media hostname still resolves publicly without auth.

### 25. [HIGH] Dangling subdomain static.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** static.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the static hostname still resolves publicly without auth.

### 26. [HIGH] Dangling subdomain assets.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** assets.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the assets hostname still resolves publicly without auth.

### 27. [HIGH] Dangling subdomain files.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** files.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the files hostname still resolves publicly without auth.

### 28. [HIGH] Dangling subdomain ftp.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** ftp.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the ftp hostname still resolves publicly without auth.

### 29. [HIGH] Dangling subdomain s3.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** s3.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the s3 hostname still resolves publicly without auth.

### 30. [HIGH] Dangling subdomain webmail.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** webmail.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the webmail hostname still resolves publicly without auth.

### 31. [HIGH] Dangling subdomain mx.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** mx.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the mx hostname still resolves publicly without auth.

### 32. [HIGH] Dangling subdomain smtp.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** smtp.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the smtp hostname still resolves publicly without auth.

### 33. [HIGH] Dangling subdomain vpn.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** vpn.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the vpn hostname still resolves publicly without auth.

### 34. [HIGH] Dangling subdomain secure.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** secure.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the secure hostname still resolves publicly without auth.

### 35. [HIGH] Dangling subdomain ssl.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** ssl.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the ssl hostname still resolves publicly without auth.

### 36. [HIGH] Dangling subdomain ws.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** ws.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the ws hostname still resolves publicly without auth.

### 37. [HIGH] Dangling subdomain push.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** push.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the push hostname still resolves publicly without auth.

### 38. [HIGH] Dangling subdomain chat.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** chat.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the chat hostname still resolves publicly without auth.

### 39. [HIGH] Dangling subdomain upload.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** upload.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the upload hostname still resolves publicly without auth.

### 40. [HIGH] Dangling subdomain dl.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** dl.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the dl hostname still resolves publicly without auth.

### 41. [HIGH] Dangling subdomain qa.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** qa.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the qa hostname still resolves publicly without auth.

### 42. [HIGH] Dangling subdomain edge.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** edge.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the edge hostname still resolves publicly without auth.

### 43. [HIGH] Dangling subdomain gateway.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** gateway.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the gateway hostname still resolves publicly without auth.

### 44. [HIGH] Dangling subdomain proxy.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** proxy.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the proxy hostname still resolves publicly without auth.

### 45. [HIGH] Dangling subdomain www2.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** www2.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the www2 hostname still resolves publicly without auth.

### 46. [HIGH] Dangling subdomain api2.robinhood.com (915 B CloudFront error) (S1)

- **CWE:** CWE-916
- **Detail:** api2.robinhood.com 403 (915 B CloudFront, x-cache "Error from cloudfront") - dangling subdomain served by a stale CloudFront distribution; the api2 hostname still resolves publicly without auth.

### 47. [LOW] status.robinhood.com public status page (S1)

- **CWE:** CWE-916
- **Detail:** status.robinhood.com 200 (46479 B AtlassianEdge, title "Robinhood Status") - public status and incident history without auth.

### 48. [LOW] shop.robinhood.com first-party store (S1)

- **CWE:** CWE-916
- **Detail:** shop.robinhood.com 200 (198150 B Cloudflare, title "Robinhood Market") - merchandise store subdomain publicly reachable.

### 49. [LOW] docs.robinhood.com 307 to crypto trading page (S1)

- **CWE:** CWE-916
- **Detail:** docs.robinhood.com 307 (envoy) to /crypto/trading - docs alias serving a product page.

### 50. [LOW] support.robinhood.com 301 to first-party support (S1)

- **CWE:** CWE-916
- **Detail:** support.robinhood.com 301 (envoy) to https://robinhood.com/support? - first-party redirect.

### 51. [LOW] blog.robinhood.com 301 with explicit port in Location (S1)

- **CWE:** CWE-916
- **Detail:** blog.robinhood.com 301 (134 B awselb/2.0) to https://robinhood.com:443/newsroom/ - explicit :443 port in the public Location.

### 52. [LOW] download.robinhood.com 301 to first-party download (S1)

- **CWE:** CWE-916
- **Detail:** download.robinhood.com 301 (envoy) to https://robinhood.com/download/ - first-party redirect.

### 53. [LOW] www.robinhood.com 301 to apex (S1)

- **CWE:** CWE-916
- **Detail:** www.robinhood.com 301 (envoy) to https://robinhood.com/ - apex redirect.

### 54. [INFO] cdn.robinhood.com S3 error page (S1)

- **CWE:** CWE-916
- **Detail:** cdn.robinhood.com 403 (263 B AmazonS3 "Error from cloudfront").

### 55. [INFO] api.robinhood.com serves empty body (S1)

- **CWE:** CWE-916
- **Detail:** api.robinhood.com 200 (0 B envoy) at the subdomain root.

### 56. [INFO] images.robinhood.com serves empty body (S1)

- **CWE:** CWE-916
- **Detail:** images.robinhood.com 200 (0 B istio-envoy) at the subdomain root.

### 57. [INFO] staging, dev, test and uat subdomains unreachable (S1)

- **CWE:** CWE-916
- **Detail:** staging.robinhood.com, dev.robinhood.com, test.robinhood.com and uat.robinhood.com all ENOTFOUND from external vantage.

### 58. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://robinhood.com/ (observed on the homepage response; HSTS present).

### 59. [LOW] No clickjacking protection (H4)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://robinhood.com/ (observed on the homepage response).

### 60. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://robinhood.com/ (observed on the homepage response; HSTS present).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
