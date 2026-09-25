# Security Audit Report — activecampaign.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://activecampaign.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | activecampaign.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 7 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 8 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 9 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://activecampaign.com/; no defense-in-depth against XSS/content injection.

### 2. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://activecampaign.com/; page may be rendered in a foreign frame.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for activecampaign.com lists 1 name(s) besides the scope host: www.activecampaign.com

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://activecampaign.com/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://activecampaign.com/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://activecampaign.com/ lists 21 URLs.

### 7. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://activecampaign.com/ -> https://www.activecampaign.com/ (positive check).

### 8. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://activecampaign.com/ exposes 28 unique Disallow path(s) (/, /.env, /apps/search/, /blog/archives, /blog/inside-activecampaign) and 6 sitemap reference(s)

### 9. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on activecampaign.com.

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://activecampaign.com/ final status: 200 (final URL https://www.activecampaign.com/).
- http://activecampaign.com/ initial status: 301.
- Certificate: DigiCert Inc GeoTrust EV RSA CA G2, valid until 2026-10-26T23:59:59+00:00.

## Active agent cross-check (latest aggressive scan on main, wave 5 - activecampaign.com)

Total findings: **16** - latest aggressive-method scan by agent-aggressive (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I1v | URL params reflected in Cloudflare challenge JS string (safely escaped, verified) | CWE-79 |
| 2 | medium | I6v | Campaign redirect endpoint /go?url= (challenge-gated, account re-test pending) | CWE-601 |
| 28 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 29 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 30 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 31 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 32 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 33 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 34 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 35 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 36 | low | H2 | Missing CSP header | CWE-1021 |
| 37 | low | H4 | No clickjacking protection | CWE-1023 |
| 38 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 39 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 40 | info | T2 | TLS certificate expiring within 33 days | CWE-295 |
| 41 | info | H5 | Missing Referrer-Policy | CWE-200 |
