# Security Audit Report — squareup.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://squareup.com/ |
| Bug bounty program | [Square](https://bugcrowd.com/square) |
| Listed scope domain | squareup.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 4, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://squareup.com/ without HttpOnly: exp_var_dg_mqls_multi_2p_v1, exp_var_pw_salesbot_entry_point_placement_experiment, exp_var_pw_signup_personalization_pricing_page_en_us_experiment_v2, exp_var_pw_signup_pricing_plan_subnav_and_cta_ctr_us_en_pricing_experiment, squareGeo. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://squareup.com/ without Secure: exp_var_dg_mqls_multi_2p_v1, exp_var_pw_salesbot_entry_point_placement_experiment, exp_var_pw_signup_personalization_pricing_page_en_us_experiment_v2, exp_var_pw_signup_pricing_plan_subnav_and_cta_ctr_us_en_pricing_experiment. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://squareup.com/ without SameSite=Lax/Strict: exp_var_dg_mqls_multi_2p_v1, exp_var_pw_salesbot_entry_point_placement_experiment, exp_var_pw_signup_personalization_pricing_page_en_us_experiment_v2, exp_var_pw_signup_pricing_plan_subnav_and_cta_ctr_us_en_pricing_experiment. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://squareup.com/; no defense-in-depth against XSS/content injection.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for squareup.com lists 13 name(s) besides the scope host: blog.squareup.com, brand.squareup.com, corner-move.squareup.com, design.squareup.com, fulfillment.squareup.com, jobs.squareup.com, localizer.squareup.com, ocr-connect.squareup.com...

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://squareup.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://squareup.com/ lists 16 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://squareup.com/ -> https://squareup.com/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://squareup.com/ exposes 39 unique Disallow path(s) (*/academy*, */app-marketplace/search?*, */appointments/api/, */appointments/book/profile/, */appointments/mapbox/) and 16 sitemap reference(s)

### 10. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on squareup.com.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://squareup.com/ final status: 200 (final URL https://squareup.com/us/en).
- http://squareup.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-10-31T19:56:17+00:00.
