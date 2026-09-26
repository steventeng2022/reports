# Security Audit Report — themarthablog.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://themarthablog.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | themarthablog.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 2, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://themarthablog.com/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://themarthablog.com/; no defense-in-depth against XSS/content injection.

### 3. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://themarthablog.com/ lists 0 URLs.

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://themarthablog.com/ exposes 1 unique Disallow path(s) (/wp-admin/) and 2 sitemap reference(s)

### 5. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on themarthablog.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://themarthablog.com/ final status: 200 (final URL https://www.themarthablog.com/).
- http://themarthablog.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-13T18:56:22+00:00.

## Active agent cross-check (phase 25 aggressive scan on main - themarthablog.com)

Total findings: **16** - latest aggressive-method scan (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | R1 | HTTP redirect to HTTP | CWE-319 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C16 | llms.txt / LLM context file exposed (v4) | CWE-538 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | info | A10b | Sitemap enumerates URLs | CWE-200 |
| 9 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 10 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 11 | info | C15 | WAF / edge fingerprint (v4) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | H7 | X-Powered-By disclosure | CWE-200 |
| 15 | info | H7 | X-Powered-By disclosure | CWE-200 |
| 16 | info | P3 | Missing security.txt | CWE-1038 |
