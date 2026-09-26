# Security Audit Report — edx.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://edx.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | edx.org |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 2, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 4 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 5 | info | H2c | HSTS not preloaded | CWE-319 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://edx.org/ without HttpOnly: authx_coin_flip, dapi_random_id. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://edx.org/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 3. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond edx.org: h97m1sqokqgvsbw1eiqol1oc6.js.wpenginepowered.com.

### 4. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 5. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://edx.org/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://edx.org/ lists 785 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://edx.org/ -> https://www.edx.org/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://edx.org/ exposes 25 unique Disallow path(s) (/*?_rsc=*, /*?utm_campaign=*, /*?utm_content=*, /*?utm_medium=*, /*?utm_source=*) and 1 sitemap reference(s)

### 10. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on edx.org.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://edx.org/ final status: 200 (final URL https://www.edx.org/).
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
