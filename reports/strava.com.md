# Security Audit Report — strava.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://strava.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | strava.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 5, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 4 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 5 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 6 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 11 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://strava.com/ without SameSite=Lax/Strict: _strava4_session. Cross-site request cookies.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://strava.com/. Clients may connect over plain HTTP on first visit.

### 3. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://strava.com/; no defense-in-depth against XSS/content injection.

### 4. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://strava.com/; browsers may MIME-sniff responses.

### 5. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://strava.com/; page may be rendered in a foreign frame.

### 6. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for strava.com lists 1 name(s) besides the scope host: *.strava.com

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://strava.com/; full URL (incl. query strings) is sent as referrer by default.

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://strava.com/; browser features (camera, mic, geolocation) unrestricted.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://strava.com/ -> https://strava.com/ (positive check).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://strava.com/ exposes 44 unique Disallow path(s) (/, /activities/*/analysis, /activities/*/embed/, /activities/*/est-power-*, /activities/*/flags/new) and 1 sitemap reference(s)

### 11. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://strava.com (3012 bytes); contact: mailto:vulnerabilities@strava.com

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://strava.com/ final status: 200 (final URL https://www.strava.com/).
- http://strava.com/ initial status: 301.
- Certificate: GoDaddy.com GoDaddy TLS Intermediate CA DV - R1v1, valid until 2027-03-19T20:56:39+00:00.

## Active agent cross-check (wave 6 aggressive scan on main - strava.com)

Total findings: **11** - latest aggressive-method scan by agent-aggressive (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | S1 | ftp.strava.com - dormant CloudFront distribution (403 + TLS failure) | CWE-916 |
| 3 | low | S1 | app.strava.com - live 301 to www.strava.com on retest | CWE-916 |
| 4 | low | S1 | status.strava.com - live Atlassian Statuspage on retest | CWE-916 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 9 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |
