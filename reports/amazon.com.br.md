# Security Audit Report — amazon.com.br

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.com.br/ |
| Bug bounty program | [Amazon](https://hackerone.com/amazonvrp) |
| Listed scope domain | amazon.com.br |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 4, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 4 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://amazon.com.br/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://amazon.com.br/; no defense-in-depth against XSS/content injection.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://amazon.com.br/; browsers may MIME-sniff responses.

### 4. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://amazon.com.br/; page may be rendered in a foreign frame.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for amazon.com.br lists 10 name(s) besides the scope host: *.by.peg.a2z.com, amazon.com, edgeflow-dp.aero.2afc17682-frontier.amazon.com.br, edgeflow.aero.2afc17682-frontier.amazon.com.br, origin-www.amazon.com.br, p-nt-www-amazon-com-br-kalias.amazon.com.br, p-y3-www-amazon-com-br-kalias.amazon.com.br, p-yo-www-amazon-com-br-kalias.amazon.com.br...

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://amazon.com.br/; full URL (incl. query strings) is sent as referrer by default.

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://amazon.com.br/; browser features (camera, mic, geolocation) unrestricted.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://amazon.com.br/ -> https://amazon.com.br/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://amazon.com.br/ exposes 22 unique Disallow path(s) (/, /-/, /gp/ask-widget/askWidget, /gp/aw/shoppingAids/, /gp/cart)

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://amazon.com.br/ final status: 202 (final URL https://www.amazon.com.br/).
- http://amazon.com.br/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-03-22T23:59:59+00:00.
