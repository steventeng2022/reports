# Security Audit Report — php.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://php.net/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | php.net |
| Test date | 2026-09-25 15:44 UTC |
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
| 6 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 7 | info | H2 | Short HSTS max-age | CWE-319 |
| 8 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 9 | info | H2c | HSTS not preloaded | CWE-319 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 14 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://php.net/ without HttpOnly: LAST_NEWS. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://php.net/ without Secure: LAST_NEWS. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://php.net/ without SameSite=Lax/Strict: LAST_NEWS. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://php.net/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://php.net/; browsers may MIME-sniff responses.

### 6. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for php.net lists 1 name(s) besides the scope host: *.php.net

### 7. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=15768000 (< 1 year): `max-age=15768000`.

### 8. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=15768000` does not cover subdomains.

### 9. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=15768000` lacks the preload directive.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://php.net/; full URL (incl. query strings) is sent as referrer by default.

### 11. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://php.net/ lists 39 URLs.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://php.net/ -> https://php.net/ (positive check).

### 13. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://php.net/ exposes 11 unique Disallow path(s) (/backend/, /distributions/, /harm/to/self, /harming/humans, /ignoring/human/orders)

### 14. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://php.net (1354 bytes); contact: https://github.com/php/php-src/security/advisories/new

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://php.net/ final status: 200 (final URL https://www.php.net/).
- http://php.net/ initial status: 301.
- Certificate: Let's Encrypt YE2, valid until 2026-11-18T04:07:27+00:00.
