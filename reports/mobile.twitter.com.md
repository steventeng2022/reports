# Security Audit Report — mobile.twitter.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mobile.twitter.com/ |
| Bug bounty program | [Twitter](https://hackerone.com/twitter) |
| Listed scope domain | mobile.twitter.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 2, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 3 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H2c | HSTS not preloaded | CWE-319 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 10 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://mobile.twitter.com/ without HttpOnly: ct0, gt, guest_id, guest_id_ads, guest_id_marketing, personalization_id. Readable by client-side script.

### 2. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://mobile.twitter.com/ without SameSite=Lax/Strict: __cf_bm, guest_id, guest_id_ads, guest_id_marketing, personalization_id. Cross-site request cookies.

### 3. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond mobile.twitter.com: .x.com, x.com.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for mobile.twitter.com lists 3 name(s) besides the scope host: *.twitter.com, cdn.syndication.twitter.com, twitter.com

### 5. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=631138519; includeSubdomains` lacks the preload directive.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://mobile.twitter.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://mobile.twitter.com/ returns 520 (no redirect to HTTPS).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://mobile.twitter.com/ exposes 9 unique Disallow path(s) (/, /*/followers, /*/following, /*?, /account/deactivated)

### 9. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://mobile.twitter.com (532 bytes); contact: https://hackerone.com/twitter

### 10. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://mobile.twitter.com/ redirects to https://x.com/.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://mobile.twitter.com/ final status: 200 (final URL https://x.com/).
- http://mobile.twitter.com/ initial status: 520.
- Certificate: Let's Encrypt YR1, valid until 2026-11-12T17:48:01+00:00.
