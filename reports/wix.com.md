# Security Audit Report — wix.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wix.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wix.com |
| Test date | 2026-09-25 19:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 5, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 6 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 9 | info | H2c | HSTS not preloaded | CWE-319 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 14 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://wix.com/ without HttpOnly: _wixCIDX, _wixUIDX, sec-fetch-unsupported, ssr-caching. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://wix.com/ without Secure: ssr-caching. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://wix.com/ without SameSite=Lax/Strict: _wixCIDX, _wixUIDX, ssr-caching. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://wix.com/; no defense-in-depth against XSS/content injection.

### 5. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://wix.com/; page may be rendered in a foreign frame.

### 6. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for wix.com lists 5 name(s) besides the scope host: *.editorx.com, *.wix.com, *.wixsite.com, editorx.com, wixsite.com (1 no longer resolve)

### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `wixsite.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 8. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 9. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://wix.com/; browser features (camera, mic, geolocation) unrestricted.

### 11. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://wix.com/ lists 1430 URLs.

### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://wix.com/ -> https://www.wix.com/ (positive check).

### 13. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://wix.com/ exposes 87 unique Disallow path(s) (*/fullscreen-page, */laboratory/conductAllInScope, /*?sort=, /*cacheKiller=, /*hubs_content) and 1 sitemap reference(s)

### 14. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on wix.com.

## Reproduction notes

- Scanned 2026-09-25 19:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://wix.com/ final status: 200 (final URL https://www.wix.com/).
- http://wix.com/ initial status: 301.
- Certificate: Let's Encrypt YR2, valid until 2026-11-06T11:34:35+00:00.

## Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before the latest passive re-audit was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 14 findings: 0 high, 0 medium, 5 low, 9 info</summary>

### Security Audit Report — wix.com

#### Scope and authorization

| Item | Value |
|---|---|
| Target | https://wix.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wix.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

#### Summary

Total findings: **14** (High: 0, Medium: 0, Low: 5, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 6 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 9 | info | H2c | HSTS not preloaded | CWE-319 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 12 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 13 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 14 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

#### Detailed findings

##### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://wix.com/ without HttpOnly: _wixCIDX, _wixUIDX, sec-fetch-unsupported, ssr-caching. Readable by client-side script.

##### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://wix.com/ without Secure: ssr-caching. Will be transmitted over HTTP if the site is reachable cleartext.

##### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://wix.com/ without SameSite=Lax/Strict: _wixCIDX, _wixUIDX, ssr-caching. Cross-site request cookies.

##### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://wix.com/; no defense-in-depth against XSS/content injection.

##### 5. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://wix.com/; page may be rendered in a foreign frame.

##### 6. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for wix.com lists 5 name(s) besides the scope host: *.editorx.com, *.wix.com, *.wixsite.com, editorx.com, wixsite.com (1 no longer resolve)

##### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `wixsite.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

##### 8. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

##### 9. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

##### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://wix.com/; browser features (camera, mic, geolocation) unrestricted.

##### 11. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://wix.com/ lists 1468 URLs.

##### 12. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://wix.com/ -> https://www.wix.com/ (positive check).

##### 13. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://wix.com/ exposes 87 unique Disallow path(s) (*/fullscreen-page, */laboratory/conductAllInScope, /*?sort=, /*cacheKiller=, /*hubs_content) and 1 sitemap reference(s)

##### 14. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on wix.com.

#### Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://wix.com/ final status: 200 (final URL https://www.wix.com/).
- http://wix.com/ initial status: 301.
- Certificate: Let's Encrypt YR2, valid until 2026-11-06T11:34:35+00:00.

#### Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before PR #1 was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 12 findings: 0 high, 1 medium, 9 low, 2 info</summary>

##### Security Audit Report — wix.com

###### Scope and authorization

| Item | Value |
|---|---|
| Target | https://wix.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wix.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

###### Summary

Total findings: **12** (High: 0, Medium: 1, Low: 9, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | S1 | mail.wix.com - managed Google Workspace alias on retest | CWE-916 |
| 3 | low | S1 | status.wix.com - live Atlassian Statuspage on retest | CWE-916 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | low | C1 | Cookies without Secure flag | CWE-614 |
| 7 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 11 | info | T2 | TLS certificate expiring within 43 days | CWE-295 |
| 12 | info | I23 | XML sitemap exposes 1398 indexed URLs | CWE-200 |

###### Detailed findings

##### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /blogtemp which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

##### 2. [LOW] mail.wix.com - managed Google Workspace alias on retest (`S1`)

- **CWE:** CWE-916
- **Detail:** mail.wix.com -> 74.125.204.121. RETEST 2026-09-25: over HTTP it 301-redirects to https://mail.google.com/a/wix.com (Server: ghs = Google) = a MANAGED Google Workspace group alias, not a dangling platform account. Over HTTPS the edge drops the TLS handshake (SNI mismatch quirk). Downgraded medium -> low (managed; TLS quirk noted).

##### 3. [LOW] status.wix.com - live Atlassian Statuspage on retest (`S1`)

- **CWE:** CWE-916
- **Detail:** status.wix.com. RETEST 2026-09-25: returns 200 (188KB) "Wix Status" served by AtlassianEdge = an active Atlassian Statuspage instance. Not dangling. Downgraded medium -> low.

##### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.wix.com/

##### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.wix.com/

##### 6. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** ssr-caching set without Secure on https://www.wix.com/

##### 7. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** ssr-caching, sec-fetch-unsupported, _wixCIDX, _wixUIDX set without HttpOnly on https://www.wix.com/

##### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.wix.com/ reflects input verbatim in body context; encoding boundary not confirmed.

##### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.wix.com/ reflects input verbatim in body context; encoding boundary not confirmed.

##### 10. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: wix.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

##### 11. [INFO] TLS certificate expiring within 43 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.wix.com (CN=*.wix.com) valid_to Nov  6 11:34:35 2026 GMT.

##### 12. [INFO] XML sitemap exposes 1398 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.wix.com/sitemap.xml returns a sitemap with 1398 URLs, aiding enumeration of the site surface.

###### Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

</details>

</details>
