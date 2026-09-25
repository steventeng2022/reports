# Security Audit Report — nytimes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nytimes.com/ |
| Bug bounty program | The New York Times |
| Listed scope domain | nytimes.com |
| Test date | 2026-09-25 06:31 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 5 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 6 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 11 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://nytimes.com/ without HttpOnly: datadome, nyt-a, nyt-gdpr, nyt-geo, nyt-purr, nyt-s-present, nyt-traceid. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://nytimes.com/ without Secure: nyt-gdpr, nyt-s-present. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://nytimes.com/ without SameSite=Lax/Strict: nyt-a, nyt-gdpr, nyt-geo, nyt-s-present, nyt-traceid. Cross-site request cookies.

### 4. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://nytimes.com/; browsers may MIME-sniff responses.

### 5. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond nytimes.com: www.nytimes.com.

### 6. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for nytimes.com lists 28 name(s) besides the scope host: *.api.dev.nytimes.com, *.api.nytimes.com, *.api.stg.nytimes.com, *.blogs.nytimes.com, *.blogs.stg.nytimes.com, *.dev.nyt.com, *.dev.nyt.net, *.dev.nytimes.com...

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://nytimes.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://nytimes.com/ -> https://nytimes.com/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://nytimes.com/ exposes 94 unique Disallow path(s) (/, /*.pdf$, /*?*&ls=, /*?*ListingID=, /*?*ProfileID=) and 25 sitemap reference(s)

### 10. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://nytimes.com (443 bytes); contact: https://help.nytimes.com/hc/en-us/articles/115015385887-Contact-Us

### 11. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://nytimes.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 06:31 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://nytimes.com/ final status: 403 (final URL https://www.nytimes.com/).
- http://nytimes.com/ initial status: 301.
- Certificate: DigiCert Inc Thawte TLS RSA CA G1, valid until 2027-03-19T23:59:59+00:00.
