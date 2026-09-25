# Security Audit Report — amazon.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.co.uk/ |
| Bug bounty program | [Amazon](https://hackerone.com/amazonvrp) |
| Listed scope domain | amazon.co.uk |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 4 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://amazon.co.uk/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://amazon.co.uk/; no defense-in-depth against XSS/content injection.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://amazon.co.uk/; browsers may MIME-sniff responses.

### 4. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://amazon.co.uk/; page may be rendered in a foreign frame.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for amazon.co.uk lists 46 name(s) besides the scope host: *.aa.peg.a2z.com, *.ab.peg.a2z.com, *.ac.peg.a2z.com, *.bz.peg.a2z.com, *.peg.a2z.com, amazon.co.jp, amazon.com, amazon.com.au... (4 no longer resolve)

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `buckeye-retail-website.amazon.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `shop.business.amazon.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 8. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `uedata.amazon.co.uk` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://amazon.co.uk/; full URL (incl. query strings) is sent as referrer by default.

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://amazon.co.uk/; browser features (camera, mic, geolocation) unrestricted.

### 11. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://amazon.co.uk/ -> https://amazon.co.uk/ (positive check).

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://amazon.co.uk/ exposes 94 unique Disallow path(s) (/, /-/, /ap/signin, /dp/e-mail-friend/, /dp/product-availability/)

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://amazon.co.uk/ final status: 202 (final URL https://www.amazon.co.uk/).
- http://amazon.co.uk/ initial status: 301.
- Certificate: DigiCert Inc GeoTrust TLS RSA CA G1, valid until 2027-04-05T23:59:59+00:00.
