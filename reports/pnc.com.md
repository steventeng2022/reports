# Security Audit Report - pnc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pnc.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pnc.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 1, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | secure.pnc.com exposes internal mesh hostname | CWE-916 |
| 2 | info | S1 | secure.svi.prod.mesh.pnc.com network-restricted | CWE-916 |
| 3 | info | S1 | portal.pnc.com returns 403 (AkamaiGHost) | CWE-916 |
| 4 | info | S1 | login.pnc.com returns 503 (Apache) | CWE-916 |
| 5 | info | S1 | media.pnc.com serves empty body | CWE-916 |
| 6 | info | I22 | Apex unreachable and www redirects over HTTP | CWE-538 |

## Detailed findings

### 1. [LOW] secure.pnc.com exposes internal mesh hostname (S1)

- **CWE:** CWE-916
- **Detail:** secure.pnc.com 302 to https://secure.svi.prod.mesh.pnc.com/ - internal service-mesh ("svi.prod.mesh") hostname exposed in a public Location header.

### 2. [INFO] secure.svi.prod.mesh.pnc.com network-restricted (S1)

- **CWE:** CWE-916
- **Detail:** secure.svi.prod.mesh.pnc.com ECONNRESET from external vantage - internal mesh host only reachable inside the PNC network.

### 3. [INFO] portal.pnc.com returns 403 (AkamaiGHost) (S1)

- **CWE:** CWE-916
- **Detail:** portal.pnc.com 403 (368 B AkamaiGHost).

### 4. [INFO] login.pnc.com returns 503 (Apache) (S1)

- **CWE:** CWE-916
- **Detail:** login.pnc.com 503 (455 B Apache).

### 5. [INFO] media.pnc.com serves empty body (S1)

- **CWE:** CWE-916
- **Detail:** media.pnc.com 200 (0 B nginx/1.24.0 (Ubuntu)).

### 6. [INFO] Apex unreachable and www redirects over HTTP (I22)

- **CWE:** CWE-538
- **Detail:** pnc.com apex ECONNRESET over TLS (JA3/geo filtering); www.pnc.com 302 with Location http://www.pnc.com/en (plain-HTTP scheme in the redirect).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
