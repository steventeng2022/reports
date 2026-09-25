# Security Audit Report — edx.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://edx.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | edx.org |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://edx.org/: MemoryError: 

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://edx.org/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2026-12-06T23:59:59+00:00.

## Active agent cross-check (wave 6 aggressive scan on main - edx.org)

Total findings: **7** - latest aggressive-method scan by agent-aggressive (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I6 | Open-redirect parameter persists apex->www 301 and is embedded in client JSON state | CWE-601 |
| 2 | medium | I20 | CORS wildcard on /api/graphql, /api/xapi, /auth (404 router) and / | CWE-942 |
| 3 | medium | I11 | Unauthenticated POST to / returns 2.5MB full app state (soft-200 + data disclosure) | CWE-200 |
| 4 | low | H1 | Missing HSTS on plain-HTTP bootstrap path | CWE-319 |
| 5 | low | I12 | 404 pages reflect request path in inline flight JSON | CWE-200 |
| 6 | info | T3 | Plain HTTP served (CloudFront 403 on apex http) | CWE-319 |
| 7 | info | A10b | Method differential: PATCH / -> 400 (915B) vs GET/POST/PUT/DELETE -> 200 (2.5MB) | CWE-200 |
