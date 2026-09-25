# Security Audit Report — ok.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ok.ru/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ok.ru |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 11 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 12 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://ok.ru/ without HttpOnly: __last_online. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://ok.ru/ without Secure: ENVOY_JSESSIONID, _okAtTraceIds. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://ok.ru/ without SameSite=Lax/Strict: ENVOY_JSESSIONID, JSESSIONID, __last_online, _okAtTraceIds, _statid, bci. Cross-site request cookies.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for ok.ru lists 41 name(s) besides the scope host: *.dating.ok.ru, *.m.odnoklassniki.ru, *.m.ok.ru, *.ms.ok.ru, *.mscu.ok.ru, *.odnoklassniki.ru, *.ok.me, *.ok.ru... (12 no longer resolve)

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `m.odnoklassniki.eu` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `ms.ok.ru` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `okl.lt` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://ok.ru/; full URL (incl. query strings) is sent as referrer by default.

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://ok.ru/; browser features (camera, mic, geolocation) unrestricted.

### 10. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://ok.ru/ -> https://ok.ru:443/ (positive check).

### 11. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://ok.ru/ exposes 33 unique Disallow path(s) (*?cmd*, *?fromTime=*, *cmd=logExternal*, *jsessionid*, *st.redirect*) and 17 sitemap reference(s)

### 12. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://ok.ru (211 bytes); contact: https://bugbounty.standoff365.com/programs/odnoklassniki_vk

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://ok.ru/ final status: 200 (final URL https://ok.ru/).
- http://ok.ru/ initial status: 301.
- Certificate: Hellenic Academic and Research Institutions CA HARICA DV TLS RSA, valid until 2026-11-07T07:49:43+00:00.
