# Security Audit Report — ikea.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ikea.com/ |
| Bug bounty program | [IKEA](https://bugs.ikea.com/) |
| Listed scope domain | ikea.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 3 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 4 | info | H2c | HSTS not preloaded | CWE-319 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://ikea.com/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://ikea.com/; browsers may MIME-sniff responses.

### 3. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond ikea.com: www.ikea.com.

### 4. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://ikea.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://ikea.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://ikea.com/ -> https://www.ikea.com/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://ikea.com/ exposes 93 unique Disallow path(s) (*&sorting=*, */3daas-rotera/*, */apply-for-finance/fragments/simulator/, */asisonline, */asisonline/*) and 1 sitemap reference(s)

### 9. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://ikea.com (185 bytes); contact: https://bugs.ikea.com/

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://ikea.com/ final status: 200 (final URL https://www.ikea.com/).
- http://ikea.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-22T01:30:11+00:00.
