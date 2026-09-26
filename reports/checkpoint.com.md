# Security Audit Report — checkpoint.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://checkpoint.com/ |
| Bug bounty program | [Check Point](https://www.checkpoint.com/white-hat/) |
| Listed scope domain | checkpoint.com |
| Test date | 2026-09-25 19:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 0, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H2c | HSTS not preloaded | CWE-319 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for checkpoint.com lists 1 name(s) besides the scope host: *.checkpoint.com

### 2. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=63072000; includeSubDomains` lacks the preload directive.

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://checkpoint.com/ -> https://checkpoint.com/ (positive check).

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://checkpoint.com/ exposes 49 unique Disallow path(s) (*eventDate=*, *eventDisplay=*, *hide_subsequent_recurrences=*, *ical=*, *outlook-ical=*) and 1 sitemap reference(s)

### 5. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on checkpoint.com.

## Reproduction notes

- Scanned 2026-09-25 19:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://checkpoint.com/ final status: 200 (final URL https://www.checkpoint.com/).
- http://checkpoint.com/ initial status: 301.
- Certificate: GlobalSign nv-sa GlobalSign GCC R3 DV TLS CA 2020, valid until 2027-01-02T06:44:08+00:00.
