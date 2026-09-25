# Security Audit Report — walmart.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://walmart.com/ |
| Bug bounty program | [Walmart Corporation](https://corporate.walmart.com/article/responsible-disclosure-policy) |
| Listed scope domain | walmart.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 5 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 6 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 7 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 8 | info | H2c | HSTS not preloaded | CWE-319 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 11 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 13 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://walmart.com/ without HttpOnly: TS012768cf, TS2a5e0c5c027, isoLoc. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://walmart.com/ without Secure: TS012768cf, TS2a5e0c5c027, isoLoc. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://walmart.com/ without SameSite=Lax/Strict: TS012768cf, TS2a5e0c5c027, akavpau_p2, isoLoc. Cross-site request cookies.

### 4. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://walmart.com/; browsers may MIME-sniff responses.

### 5. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond walmart.com: .www.walmart.com.

### 6. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for walmart.com lists 6 name(s) besides the scope host: beta.walmart.com, grocery.walmart.com, walmart.pharmacy, walmartspecialty.pharmacy, www.wal-mart.com, www.walmart.com

### 7. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 8. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://walmart.com/; full URL (incl. query strings) is sent as referrer by default.

### 10. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://walmart.com/ lists 0 URLs.

### 11. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://walmart.com/ -> https://www.walmart.com/ (positive check).

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://walmart.com/ exposes 57 unique Disallow path(s) (*/api/wpa, */midas/*, */undefined/*, /0/, /55875582/walmart-us/catalog/) and 34 sitemap reference(s)

### 13. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://walmart.com (247 bytes); contact: https://corporate.walmart.com/article/responsible-disclosure-policy

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://walmart.com/ final status: 200 (final URL https://www.walmart.com/).
- http://walmart.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign GCC E46 OV TLS CA 2025, valid until 2027-02-11T09:58:01+00:00.
