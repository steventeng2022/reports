# Security Audit Report — es.wikipedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://es.wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | es.wikipedia.org |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 2, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 8 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://es.wikipedia.org/ without SameSite=Lax/Strict: WMF-Uniq. Cross-site request cookies.

### 2. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://es.wikipedia.org/; page may be rendered in a foreign frame.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for es.wikipedia.org lists 41 name(s) besides the scope host: *.m.mediawiki.org, *.m.wikibooks.org, *.m.wikidata.org, *.m.wikimedia.org, *.m.wikinews.org, *.m.wikipedia.org, *.m.wikiquote.org, *.m.wikisource.org...

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://es.wikipedia.org/; full URL (incl. query strings) is sent as referrer by default.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://es.wikipedia.org/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://es.wikipedia.org/ -> https://es.wikipedia.org/ (positive check).

### 7. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://es.wikipedia.org/ exposes 255 unique Disallow path(s) (#, /, /api/, /trap/, /w/) and 1 sitemap reference(s)

### 8. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://es.wikipedia.org (222 bytes); contact: mailto:security@wikimedia.org

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://es.wikipedia.org/ final status: 200 (final URL https://es.wikipedia.org/wiki/Wikipedia:Portada).
- http://es.wikipedia.org/ initial status: 301.
- Certificate: Let's Encrypt YE2, valid until 2026-11-03T19:15:40+00:00.

## Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before PR #1 was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 20 findings: 0 high, 1 medium, 17 low, 2 info</summary>

### Security Audit Report — es.wikipedia.org

#### Scope and authorization

| Item | Value |
|---|---|
| Target | https://es.wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | es.wikipedia.org |
| Test date | 2026-09-25 03:24 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

#### Summary

Total findings: **20** (High: 0, Medium: 1, Low: 17, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I2 | Input reflected in <title> of 404/edit pages - escape vectors sanitized on retest | CWE-79 |
| 2 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
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
| 18 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 19 | info | T2 | TLS certificate expiring within 40 days | CWE-295 |
| 20 | info | H5 | Missing Referrer-Policy | CWE-200 |

#### Detailed findings

##### 1. [LOW] Input reflected in <title> of 404/edit pages - escape vectors sanitized on retest (`I2`)

- **CWE:** CWE-79
- **Detail:** ?title=<token> on /w/index.php reflects the token UNENCODED in the page <title> of the 404 ("<tok> - Wikipedia, la enciclopedia libre") and 200 edit ("Creacion de «<tok>»") pages. RETEST 2026-09-25: title-escape was probed with ?title=%22%3e<script>alert(1)</script> and ?title=%3c%2ftitle%3e<script>alert(1)</script> - both return the generic sanitized 404 titled "Título incorrecto" (MediaWiki strips < and > from the title). Backslash/quote (\" and \") ARE preserved raw inside <title> but cannot terminate a CDATA title tag. /wiki/<title> normalizes special chars (301 to /wiki/%22_onfocus... = plain title). Verdict: no XSS breakout; kept as low (raw reflection into <title> for safe charset only).

##### 2. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /api/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

##### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://es.wikipedia.org/wiki/Wikipedia:Portada

##### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** GeoIP, NetworkProbeLimit set without HttpOnly on https://es.wikipedia.org/wiki/Wikipedia:Portada

##### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter modules on https://es.wikipedia.org/w/load.php reflects input verbatim in body context; encoding boundary not confirmed.

##### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://es.wikipedia.org/w/api.php reflects input verbatim in body context; encoding boundary not confirmed.

##### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://es.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://es.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://es.wikipedia.org/s reflects input verbatim in body context; encoding boundary not confirmed.

##### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://es.wikipedia.org/ reflects input verbatim in body context; encoding boundary not confirmed.

##### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://es.wikipedia.org/results reflects input verbatim in body context; encoding boundary not confirmed.

##### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.wikipedia.org/redirect reflects input verbatim in body context; encoding boundary not confirmed.

##### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://es.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.wikipedia.org/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://es.wikipedia.org/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.wikipedia.org/link reflects input verbatim in body context; encoding boundary not confirmed.

##### 18. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: es.wikipedia.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

##### 19. [INFO] TLS certificate expiring within 40 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for es.wikipedia.org (CN=*.wikipedia.org) valid_to Nov  3 19:15:40 2026 GMT.

##### 20. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://es.wikipedia.org/wiki/Wikipedia:Portada

#### Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

</details>
