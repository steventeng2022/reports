# Security Audit Report — feeds.feedburner.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://feeds.feedburner.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | feeds.feedburner.com |
| Test date | 2026-09-25 02:55 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 2, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 9 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 12 | info | X2 | HTTPS homepage returned HTTP 404 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://feeds.feedburner.com/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://feeds.feedburner.com/; page may be rendered in a foreign frame.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for feeds.feedburner.com lists 406 name(s) besides the scope host: *.actions.google.com, *.adgoogle.net, *.admeld.com, *.advertiserscommunity.com, *.adwords-community.com, *.adwordsexpress.com, *.aiinfra.google, *.angulardart.org... (8 no longer resolve)

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `accounts.mandiant.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `appbridge.it` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `cloudfunctions.net` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://feeds.feedburner.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://feeds.feedburner.com/ lists 0 URLs.

### 9. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://feeds.feedburner.com/ returns 404 (no redirect to HTTPS).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://feeds.feedburner.com/ exposes 0 unique Disallow path(s)

### 11. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on feeds.feedburner.com.

### 12. [INFO] HTTPS homepage returned HTTP 404 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://feeds.feedburner.com/ responded 404 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 02:55 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://feeds.feedburner.com/ final status: 404 (final URL https://feeds.feedburner.com/).
- http://feeds.feedburner.com/ initial status: 404.
- Certificate: Google Trust Services WE2, valid until 2026-12-03T19:22:33+00:00.
