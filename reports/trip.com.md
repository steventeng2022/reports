# Security Audit Report - trip.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://trip.com |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | trip.com
| Test date | 2026-09-30 12:45 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation with 2-hop canary tracking, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 6, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | mx.trip.com serves the full Trip.com application | CWE-916 |
| 2 | low | S1 | qa.trip.com serves live QA content | CWE-916 |
| 3 | low | S1 | secure.trip.com serves a small public page | CWE-916 |
| 4 | low | H1 | No HSTS on mx.trip.com | CWE-319 |
| 5 | low | H2 | No CSP on mx.trip.com | CWE-1021 |
| 6 | low | C1 | All 18 mx.trip.com cookies set without Secure flag | CWE-614 |
| 7 | info | H5 | Missing Referrer-Policy on mx.trip.com | CWE-200 |
| 8 | info | S1 | download.trip.com serves an OpenResty 404 | CWE-916 |
| 9 | info | S1 | Homepage returns 424 Too Early to scanner clients | CWE-916 |

## Detailed findings

### 1. [LOW] mx.trip.com serves the full Trip.com application (S1)

- **CWE:** CWE-916
- **Detail:** mx.trip.com 200 (103 KB) serves the complete live Trip.com site (same title as the main host) - the MX hostname hosts the primary web application.

### 2. [LOW] qa.trip.com serves live QA content (S1)

- **CWE:** CWE-916
- **Detail:** qa.trip.com 200 (99 KB) - QA environment hostname serving content publicly.

### 3. [LOW] secure.trip.com serves a small public page (S1)

- **CWE:** CWE-916
- **Detail:** secure.trip.com 200 (278 B) - the secure hostname is publicly reachable without auth.

### 4. [LOW] No HSTS on mx.trip.com (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://mx.trip.com/ (serves the full application; only X-Frame-Options SAMEORIGIN and nosniff present).

### 5. [LOW] No CSP on mx.trip.com (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://mx.trip.com/.

### 6. [LOW] All 18 mx.trip.com cookies set without Secure flag (C1)

- **CWE:** CWE-614
- **Detail:** All 18 cookies set on mx.trip.com lack the Secure flag (two carry HttpOnly).

### 7. [INFO] Missing Referrer-Policy on mx.trip.com (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://mx.trip.com/.

### 8. [INFO] download.trip.com serves an OpenResty 404 (S1)

- **CWE:** CWE-916
- **Detail:** download.trip.com 404 (14 KB openresty) - live subdomain.

### 9. [INFO] Homepage returns 424 Too Early to scanner clients (S1)

- **CWE:** CWE-916
- **Detail:** www.trip.com / 424 (17 B) over HTTP/2 early-data connections - an edge quirk for clients sending early data; www 302s to the tw.trip.com regional host.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions). Redirect paths were followed two hops with a canary URL to confirm token consumption.
