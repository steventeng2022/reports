# Security Audit Report — boredpanda.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://boredpanda.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | boredpanda.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 7, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 6 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 7 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 8 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 9 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 14 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://boredpanda.com/ without HttpOnly: experimentId, experiment_bpp_carousel_v2, experiment_post_poll_totals, experiment_top_post_in_feed, experiment_top_posts_split_test. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://boredpanda.com/ without Secure: experimentId, experiment_bpp_carousel_v2, experiment_post_poll_totals, experiment_top_post_in_feed, experiment_top_posts_split_test. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://boredpanda.com/ without SameSite=Lax/Strict: experimentId, experiment_bpp_carousel_v2, experiment_post_poll_totals, experiment_top_post_in_feed, experiment_top_posts_split_test. Cross-site request cookies.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://boredpanda.com/. Clients may connect over plain HTTP on first visit.

### 5. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://boredpanda.com/; no defense-in-depth against XSS/content injection.

### 6. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://boredpanda.com/; browsers may MIME-sniff responses.

### 7. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://boredpanda.com/; page may be rendered in a foreign frame.

### 8. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond boredpanda.com: .www.boredpanda.com.

### 9. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for boredpanda.com lists 3 name(s) besides the scope host: mirror.boredpanda.com, www.boredpanda.com, www.mirror.boredpanda.com

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://boredpanda.com/; full URL (incl. query strings) is sent as referrer by default.

### 11. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://boredpanda.com/ lists 11 URLs.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://boredpanda.com/ -> https://www.boredpanda.com:443/ (positive check).

### 13. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://boredpanda.com/ exposes 8 unique Disallow path(s) (/, /*wp-admin/, /*wp-content, /*wp-includes, /*wp-json) and 6 sitemap reference(s)

### 14. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on boredpanda.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://boredpanda.com/ final status: 200 (final URL https://www.boredpanda.com/).
- http://boredpanda.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-02-27T23:59:59+00:00.
