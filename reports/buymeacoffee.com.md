# Security Audit Report — buymeacoffee.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://buymeacoffee.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | buymeacoffee.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
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
- **Detail:** No Strict-Transport-Security header on https://buymeacoffee.com/. Clients may connect over plain HTTP on first visit.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://buymeacoffee.com/; no defense-in-depth against XSS/content injection.

### 3. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://buymeacoffee.com/; browsers may MIME-sniff responses.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for buymeacoffee.com lists 1 name(s) besides the scope host: *.buymeacoffee.com

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://buymeacoffee.com/; full URL (incl. query strings) is sent as referrer by default.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://buymeacoffee.com/; browser features (camera, mic, geolocation) unrestricted.

### 7. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://buymeacoffee.com/ lists 312 URLs.

### 8. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://buymeacoffee.com/ -> https://buymeacoffee.com/ (positive check).

### 9. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://buymeacoffee.com/ exposes 1 unique Disallow path(s) (/app/*) and 1 sitemap reference(s)

### 10. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on buymeacoffee.com.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://buymeacoffee.com/ final status: 200 (final URL https://buymeacoffee.com/).
- http://buymeacoffee.com/ initial status: 301.
- Certificate: Let's Encrypt YE1, valid until 2026-11-04T22:04:00+00:00.

## Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before PR #1 was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 35 findings: 0 high, 0 medium, 32 low, 3 info</summary>

### Security Audit Report — buymeacoffee.com

#### Scope and authorization

| Item | Value |
|---|---|
| Target | https://buymeacoffee.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | buymeacoffee.com |
| Test date | 2026-09-25 03:24 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

#### Summary

Total findings: **35** (High: 0, Medium: 0, Low: 32, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I10 | /actuator soft-200 catch-all - SPA index HTML, not Spring actuator | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 15 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 16 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 17 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 18 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 19 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 20 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 21 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 22 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 23 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 24 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 25 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 26 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 27 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 28 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 29 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 30 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 31 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 32 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 33 | info | T2 | TLS certificate expiring within 41 days | CWE-295 |
| 34 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 35 | info | H5 | Missing Referrer-Policy | CWE-200 |

#### Detailed findings

##### 1. [LOW] /actuator soft-200 catch-all - SPA index HTML, not Spring actuator (`I10`)

- **CWE:** CWE-538
- **Detail:** Initial scan: GET https://buymeacoffee.com/actuator returned 200 (157930B) matching a soft-200 signature. RETEST 2026-09-25: apex /actuator = 200 text/html 157930B (the SPA index page, byte-identical to /), /health = 200 155887B HTML, /actuator/ = 301, /actuator/env | /info = 404 HTML. Every arbitrary path on the apex returns the SPA index (client-side routing catch-all) - there is no Spring Boot actuator behind it. Downgraded medium -> low (hygiene: soft-200 catch-all makes path probing ambiguous).

##### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://buymeacoffee.com/

##### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://buymeacoffee.com/

##### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://buymeacoffee.com/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://buymeacoffee.com/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://buymeacoffee.com/s reflects input verbatim in body context; encoding boundary not confirmed.

##### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://buymeacoffee.com/results reflects input verbatim in body context; encoding boundary not confirmed.

##### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

##### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://buymeacoffee.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://buymeacoffee.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/link reflects input verbatim in body context; encoding boundary not confirmed.

##### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/out reflects input verbatim in body context; encoding boundary not confirmed.

##### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/u reflects input verbatim in body context; encoding boundary not confirmed.

##### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/share reflects input verbatim in body context; encoding boundary not confirmed.

##### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://buymeacoffee.com/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://buymeacoffee.com/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://buymeacoffee.com/s reflects input verbatim in body context; encoding boundary not confirmed.

##### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://buymeacoffee.com/results reflects input verbatim in body context; encoding boundary not confirmed.

##### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

##### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://buymeacoffee.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://buymeacoffee.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/link reflects input verbatim in body context; encoding boundary not confirmed.

##### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/out reflects input verbatim in body context; encoding boundary not confirmed.

##### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/u reflects input verbatim in body context; encoding boundary not confirmed.

##### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/share reflects input verbatim in body context; encoding boundary not confirmed.

##### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://buymeacoffee.com/view reflects input verbatim in body context; encoding boundary not confirmed.

##### 31. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://buymeacoffee.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

##### 32. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: buymeacoffee.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

##### 33. [INFO] TLS certificate expiring within 41 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for buymeacoffee.com (CN=buymeacoffee.com) valid_to Nov  4 22:04:00 2026 GMT.

##### 34. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://buymeacoffee.com/

##### 35. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://buymeacoffee.com/

#### Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

</details>
