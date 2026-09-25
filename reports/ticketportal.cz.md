# Security Audit Report — ticketportal.cz

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ticketportal.cz/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | ticketportal.cz |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 4, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 4 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://ticketportal.cz/ without SameSite=Lax/Strict: __RequestVerificationToken. Cross-site request cookies.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://ticketportal.cz/. Clients may connect over plain HTTP on first visit.

### 3. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://ticketportal.cz/; no defense-in-depth against XSS/content injection.

### 4. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://ticketportal.cz/; browsers may MIME-sniff responses.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for ticketportal.cz lists 1 name(s) besides the scope host: *.ticketportal.cz

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://ticketportal.cz/; full URL (incl. query strings) is sent as referrer by default.

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://ticketportal.cz/; browser features (camera, mic, geolocation) unrestricted.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://ticketportal.cz/ -> https://www.ticketportal.cz/ (positive check).

### 9. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on ticketportal.cz.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://ticketportal.cz/ final status: 200 (final URL https://www.ticketportal.cz/).
- http://ticketportal.cz/ initial status: 302.
- Certificate: Let's Encrypt YE2, valid until 2026-12-06T19:58:58+00:00.
