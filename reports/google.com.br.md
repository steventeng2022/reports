# Security Audit Report — google.com.br

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://google.com.br/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | google.com.br |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 5, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 7 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 8 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 9 | info | H2c | HSTS not preloaded | CWE-319 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 13 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 14 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://google.com.br/ without HttpOnly: SEARCH_SAMESITE, __Secure-STRP. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://google.com.br/ without Secure: SEARCH_SAMESITE. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://google.com.br/ without SameSite=Lax/Strict: NID. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://google.com.br/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://google.com.br/; browsers may MIME-sniff responses.

### 6. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond google.com.br: .google.com.

### 7. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for google.com.br lists 1 name(s) besides the scope host: *.google.com.br

### 8. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 9. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://google.com.br/; full URL (incl. query strings) is sent as referrer by default.

### 11. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://google.com.br/ lists 22 URLs.

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://google.com.br/ exposes 174 unique Disallow path(s) (/?, /?hl=*&, /?hl=*&*&gws_rd=ssl, /about/careers/applications-a/jobs/results, /about/careers/applications/candidate-prep) and 1 sitemap reference(s)

### 13. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://google.com.br (275 bytes); contact: https://g.co/vulnz

### 14. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://google.com.br/ redirects to https://www.google.com/.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://google.com.br/ final status: 200 (final URL https://www.google.com/).
- http://google.com.br/ initial status: 301.
- Certificate: Google Trust Services WE2, valid until 2026-12-03T19:24:36+00:00.
