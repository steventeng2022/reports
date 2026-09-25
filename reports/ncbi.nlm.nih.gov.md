# Security Audit Report — ncbi.nlm.nih.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ncbi.nlm.nih.gov/ |
| Bug bounty program | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| Listed scope domain | ncbi.nlm.nih.gov |
| Test date | 2026-09-25 02:55 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 1, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://ncbi.nlm.nih.gov/; browsers may MIME-sniff responses.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for ncbi.nlm.nih.gov lists 1 name(s) besides the scope host: *.ncbi.nlm.nih.gov

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://ncbi.nlm.nih.gov/; browser features (camera, mic, geolocation) unrestricted.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://ncbi.nlm.nih.gov/ -> https://ncbi.nlm.nih.gov:443/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://ncbi.nlm.nih.gov/ exposes 90 unique Disallow path(s) (*, /COG, /Coffeebreak, /Entrez, /IEB/ToolBox/SB) and 20 sitemap reference(s)

### 6. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on ncbi.nlm.nih.gov.

## Reproduction notes

- Scanned 2026-09-25 02:55 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://ncbi.nlm.nih.gov/ final status: 200 (final URL https://ncbi.nlm.nih.gov/).
- http://ncbi.nlm.nih.gov/ initial status: 301.
- Certificate: GoDaddy.com GoDaddy TLS Intermediate CA DV - R1v1, valid until 2027-03-14T16:31:19+00:00.
