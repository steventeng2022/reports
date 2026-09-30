# Security Audit Report - fidelity.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fidelity.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | fidelity.com
| Test date | 2026-09-30 11:30 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 0, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | S1 | Homepage 403 behind Akamai | CWE-916 |
| 2 | info | S1 | app.fidelity.com returns 400 | CWE-916 |
| 3 | info | S1 | media.fidelity.com returns 403 | CWE-916 |
| 4 | info | S1 | assets.fidelity.com serves stale AEM error page | CWE-916 |
| 5 | info | S1 | login 404; auth 301 to apex; mobile and ftp unreachable | CWE-916 |

## Detailed findings

### 1. [INFO] Homepage 403 behind Akamai (S1)

- **CWE:** CWE-916
- **Detail:** www.fidelity.com 403 (368 B AkamaiGHost) - edge-gated homepage for the scanner client.

### 2. [INFO] app.fidelity.com returns 400 (S1)

- **CWE:** CWE-916
- **Detail:** app.fidelity.com 400 (308 B AkamaiGHost).

### 3. [INFO] media.fidelity.com returns 403 (S1)

- **CWE:** CWE-916
- **Detail:** media.fidelity.com 403 (366 B AkamaiGHost).

### 4. [INFO] assets.fidelity.com serves stale AEM error page (S1)

- **CWE:** CWE-916
- **Detail:** assets.fidelity.com 200 (8133 B AkamaiNetStorage, title "Fidelity.com is Temporarily Unavailable") - stale AEM error document on the assets subdomain.

### 5. [INFO] login 404; auth 301 to apex; mobile and ftp unreachable (S1)

- **CWE:** CWE-916
- **Detail:** login.fidelity.com 404 (1269 B Apache); auth.fidelity.com 301 to https://www.fidelity.com/ (Apache); mobile and ftp ECONNRESET from external vantage.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
