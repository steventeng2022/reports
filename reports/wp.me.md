# Security Audit Report — wp.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wp.me/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | wp.me |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 4 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 11 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 12 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://wp.me/ without HttpOnly: explat_test_aa_weekly_lohp_2026_week_39, tk_ai, tk_ai_explat, tk_qs, wpcom_lohp_plugins_banner_202609. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://wp.me/ without SameSite=Lax/Strict: explat_test_aa_weekly_lohp_2026_week_39, tk_ai, tk_ai_explat, wpcom_lohp_plugins_banner_202609. Cross-site request cookies.

### 3. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://wp.me/; no defense-in-depth against XSS/content injection.

### 4. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond wp.me: .wordpress.com.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for wp.me lists 1 name(s) besides the scope host: www.wp.me (1 no longer resolve)

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `www.wp.me` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; preload` does not cover subdomains.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://wp.me/; full URL (incl. query strings) is sent as referrer by default.

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://wp.me/; browser features (camera, mic, geolocation) unrestricted.

### 10. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://wp.me/ -> https://wordpress.com/ (positive check).

### 11. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on wp.me.

### 12. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://wp.me/ redirects to https://wordpress.com/.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://wp.me/ final status: 200 (final URL https://wordpress.com/).
- http://wp.me/ initial status: 302.
- Certificate: Let's Encrypt YE1, valid until 2026-11-08T19:43:49+00:00.
