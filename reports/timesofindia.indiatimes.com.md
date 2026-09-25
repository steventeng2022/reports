# Security Audit Report — timesofindia.indiatimes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://timesofindia.indiatimes.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | timesofindia.indiatimes.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H2 | Short HSTS max-age | CWE-319 |
| 4 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 5 | info | H2c | HSTS not preloaded | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://timesofindia.indiatimes.com/; browsers may MIME-sniff responses.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for timesofindia.indiatimes.com lists 98 name(s) besides the scope host: agri-preprod.economictimes.indiatimes.com, agri.economictimes.indiatimes.com, ai-stage.etmasterclass.com, ai.etmasterclass.com, api-newscard.timesofindia.com, autolytics-cms.economictimes.indiatimes.com, b2b-cms.economictimes.indiatimes.com, bengali.economictimes.com...

### 3. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=86400 (< 1 year): `max-age=86400`.

### 4. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=86400` does not cover subdomains.

### 5. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=86400` lacks the preload directive.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://timesofindia.indiatimes.com/; full URL (incl. query strings) is sent as referrer by default.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://timesofindia.indiatimes.com/ -> https://timesofindia.indiatimes.com/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://timesofindia.indiatimes.com/ exposes 164 unique Disallow path(s) (*,page, *-mostviwed*, */affiliate_amazon.cms*, */affiliates_content*, */affiliates_content.cms*) and 11 sitemap reference(s)

### 9. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on timesofindia.indiatimes.com.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://timesofindia.indiatimes.com/ final status: 200 (final URL https://timesofindia.indiatimes.com/).
- http://timesofindia.indiatimes.com/ initial status: 301.
- Certificate: Let's Encrypt YR1, valid until 2026-10-27T05:38:36+00:00.
