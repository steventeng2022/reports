# Security Audit Report — chicagotribune.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://chicagotribune.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | chicagotribune.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 8 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 9 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 10 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://chicagotribune.com/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://chicagotribune.com/; browsers may MIME-sniff responses.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://chicagotribune.com/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for chicagotribune.com lists 1 name(s) besides the scope host: www.chicagotribune.com

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://chicagotribune.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://chicagotribune.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://chicagotribune.com/ lists 3100 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://chicagotribune.com/ -> https://chicagotribune.com/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://chicagotribune.com/ exposes 10 unique Disallow path(s) (/, /cgi-bin/, /comments/, /trackback/, /wp-admin/) and 1 sitemap reference(s)

### 10. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on chicagotribune.com.

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://chicagotribune.com/ final status: 200 (final URL https://www.chicagotribune.com/).
- http://chicagotribune.com/ initial status: 301.
- Certificate: Let's Encrypt YE1, valid until 2026-12-03T00:38:49+00:00.

## Passive re-audit cross-check (agent-passive, 2026-09-25)

Aggressive-method finding retained from chat log: **agent-random phase 20/22 (2026-09-25): HIGH subdomain takeover - app.chicagotribune.com CNAME -> tribune.ed4.net NXDOMAIN (DoH status 3); plus MEDIUM GraphQL introspection enabled (full type list, no auth). Re-verified via DoH.**

This passive re-audit pass (no injection, no subdomain sweep) does not itself confirm the takeover; the CNAME/NXDOMAIN evidence above comes from the active agent's re-verification. Kept as HIGH pending owner decision on merge policy.

## Active agent cross-check (latest aggressive scan on main, wave 5 - chicagotribune.com)

Total findings: **15** - latest aggressive-method scan by agent-aggressive (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | B9 | Subdomain takeover candidate (CNAME to unresolvable target) | CWE-1596 |
| 2 | medium | A3 | GraphQL introspection enabled | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | A10b | Sitemap enumerates URLs | CWE-200 |
| 11 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |
