# Security Audit Report — support.cloudflare.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://support.cloudflare.com/ |
| Bug bounty program | [Cloudflare](https://hackerone.com/cloudflare) |
| Listed scope domain | support.cloudflare.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 3 | info | H2 | Short HSTS max-age | CWE-319 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt protected | CWE-200 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 8 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |
| 9 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://support.cloudflare.com/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond support.cloudflare.com: dash.cloudflare.com.

### 3. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=86400 (< 1 year): `max-age=86400; includeSubDomains`.

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=86400; includeSubDomains` lacks the preload directive.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://support.cloudflare.com/ -> https://dash.cloudflare.com/?to=/:account/support (positive check).

### 6. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on support.cloudflare.com.

### 8. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://support.cloudflare.com/ responded 403 (passive check only; no further probing).

### 9. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://support.cloudflare.com/ redirects to https://dash.cloudflare.com/?to=/:account/support.

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://support.cloudflare.com/ final status: 403 (final URL https://dash.cloudflare.com/?to=/:account/support).
- http://support.cloudflare.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-03T09:25:45+00:00.
