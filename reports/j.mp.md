# Security Audit Report — j.mp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://j.mp/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | j.mp |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N3 | Plain HTTP returns non-redirect status | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 9 | info | X2 | HTTPS homepage returned HTTP 404 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://j.mp/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://j.mp/; no defense-in-depth against XSS/content injection.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://j.mp/; browsers may MIME-sniff responses.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://j.mp/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://j.mp/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] Plain HTTP returns non-redirect status (`N3`)

- **CWE:** CWE-319
- **Detail:** http://j.mp/ returns 404 (no redirect to HTTPS).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://j.mp/ exposes 0 unique Disallow path(s)

### 8. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on j.mp.

### 9. [INFO] HTTPS homepage returned HTTP 404 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://j.mp/ responded 404 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://j.mp/ final status: 404 (final URL https://j.mp/).
- http://j.mp/ initial status: 404.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-02-10T23:59:59+00:00.

## Active agent cross-check (phase 25 aggressive scan on main - j.mp)

Total findings: **15** - latest aggressive-method scan (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | R2 | No HTTP->HTTPS redirect | CWE-319 |
| 2 | low | C12b | Ancillary file exposure (v4 sweep) | CWE-538 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | I7 | Host header reflection | CWE-200 |
| 15 | info | P3 | Missing security.txt | CWE-1038 |
