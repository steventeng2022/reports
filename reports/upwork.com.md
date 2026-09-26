# Security Audit Report — upwork.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://upwork.com/ |
| Bug bounty program | [Upwork](https://bugcrowd.com/upwork) |
| Listed scope domain | upwork.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 1, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 6 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://upwork.com/; no defense-in-depth against XSS/content injection.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for upwork.com lists 3 name(s) besides the scope host: *.email.upwork.com, *.t.upwork.com, *.upwork.com

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://upwork.com/ -> https://www.upwork.com (positive check).

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://upwork.com/ exposes 258 unique Disallow path(s) (*/login*?*, */signup*?*, /, /*/comments/, /*/feed/) and 1 sitemap reference(s)

### 5. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://upwork.com (291 bytes); contact: https://bugcrowd.com/upwork

### 6. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://upwork.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://upwork.com/ final status: 403 (final URL https://www.upwork.com/).
- http://upwork.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-07T05:52:39+00:00.
