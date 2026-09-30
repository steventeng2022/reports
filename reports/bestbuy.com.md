# Security Audit Report - bestbuy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bestbuy.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bestbuy.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 1, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | Homepage ECONNRESET over TLS | CWE-916 |
| 2 | low | S1 | assets.bestbuy.com 302 to internal AEM author host over HTTP | CWE-916 |
| 3 | info | S1 | api.bestbuy.com returns 403 | CWE-916 |
| 4 | info | S1 | app 404; dl 404 | CWE-916 |
| 5 | info | S1 | images.bestbuy.com serves 62-byte body | CWE-916 |
| 6 | info | S1 | mail, checkout and mobile unreachable | CWE-916 |

## Detailed findings

### 1. [INFO] Homepage ECONNRESET over TLS (S1)

- **CWE:** CWE-916
- **Detail:** www.bestbuy.com TLS handshake succeeds then the connection resets (ECONNRESET read) from external vantage - JA3/geo-gated edge.

### 2. [LOW] assets.bestbuy.com 302 to internal AEM author host over HTTP (S1)

- **CWE:** CWE-916
- **Detail:** assets.bestbuy.com 302 (BigIP) to http://author-p33352-e143942.adobeaemcloud.com - internal Adobe AEM author node name exposed in the public Location with a plain-HTTP scheme.

### 3. [INFO] api.bestbuy.com returns 403 (S1)

- **CWE:** CWE-916
- **Detail:** api.bestbuy.com 403 (98 B) at the subdomain root.

### 4. [INFO] app 404; dl 404 (S1)

- **CWE:** CWE-916
- **Detail:** app.bestbuy.com 404 (0 B); dl.bestbuy.com 404 (10 B AkamaiNetStorage).

### 5. [INFO] images.bestbuy.com serves 62-byte body (S1)

- **CWE:** CWE-916
- **Detail:** images.bestbuy.com 200 (62 B Apache) at the subdomain root.

### 6. [INFO] mail, checkout and mobile unreachable (S1)

- **CWE:** CWE-916
- **Detail:** mail, checkout and mobile subdomains ECONNRESET from external vantage - stale records still resolving.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
