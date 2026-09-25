# Security Audit Report — linktr.ee

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://linktr.ee/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | linktr.ee |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://linktr.ee/. Clients may connect over plain HTTP on first visit.

### 2. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://linktr.ee/; browser features (camera, mic, geolocation) unrestricted.

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://linktr.ee/ -> https://linktr.ee/ (positive check).

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://linktr.ee/ exposes 5 unique Disallow path(s) (/, /admin$, /admin/, /admin?, /s/about/trust-center/report) and 3 sitemap reference(s)

### 5. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on linktr.ee.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://linktr.ee/ final status: 200 (final URL https://linktr.ee/).
- http://linktr.ee/ initial status: 301.
- Certificate: Let's Encrypt YR1, valid until 2026-11-27T01:38:01+00:00.

## Active agent cross-check (wave 7-9 aggressive scan on main - linktr.ee)

Total findings: **5** - latest aggressive-method scan (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | I11 | GraphQL introspection enabled on /api/graphql | CWE-200 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
