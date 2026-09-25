# Security Audit Report — discordapp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://discordapp.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | discordapp.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 6 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for discordapp.com lists 1 name(s) besides the scope host: *.discordapp.com

### 2. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://discordapp.com/; full URL (incl. query strings) is sent as referrer by default.

### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://discordapp.com/ -> https://discordapp.com/ (positive check).

### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://discordapp.com/ exposes 25 unique Disallow path(s) (/, /api, /api/, /authorize-ip, /authorize-ip/) and 7 sitemap reference(s)

### 5. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://discordapp.com (247 bytes); contact: https://discord.com/security

### 6. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://discordapp.com/ redirects to https://discord.com/.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://discordapp.com/ final status: 200 (final URL https://discord.com/).
- http://discordapp.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-26T23:09:41+00:00.

## Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before the latest passive re-audit was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 6 findings: 0 high, 0 medium, 0 low, 6 info</summary>

### Security Audit Report — discordapp.com

#### Scope and authorization

| Item | Value |
|---|---|
| Target | https://discordapp.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | discordapp.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

#### Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 3 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 4 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 5 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |
| 6 | info | X3 | HTTPS root redirects to different host | CWE-200 |

#### Detailed findings

##### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for discordapp.com lists 1 name(s) besides the scope host: *.discordapp.com

##### 2. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://discordapp.com/; full URL (incl. query strings) is sent as referrer by default.

##### 3. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://discordapp.com/ -> https://discordapp.com/ (positive check).

##### 4. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://discordapp.com/ exposes 25 unique Disallow path(s) (/, /api, /api/, /authorize-ip, /authorize-ip/) and 7 sitemap reference(s)

##### 5. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://discordapp.com (247 bytes); contact: https://discord.com/security

##### 6. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://discordapp.com/ redirects to https://discord.com/.

#### Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://discordapp.com/ final status: 200 (final URL https://discord.com/).
- http://discordapp.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-26T23:09:41+00:00.

#### Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before PR #1 was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 33 findings: 0 high, 1 medium, 27 low, 5 info</summary>

##### Security Audit Report — discordapp.com

###### Scope and authorization

| Item | Value |
|---|---|
| Target | https://discordapp.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | discordapp.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

###### Summary

Total findings: **33** (High: 0, Medium: 1, Low: 27, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | I4 | Input reflected in search input value attr - fully entity-encoded on retest | CWE-79 |
| 3 | low | I4 | Input reflected in search input value attr - fully entity-encoded on retest | CWE-79 |
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
| 28 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 29 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 30 | info | I26 | humans.txt exposed (team/contact enumeration) | CWE-200 |
| 31 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |
| 32 | info | I26 | OpenID configuration exposed (identity endpoints enumerable) | CWE-200 |

###### Detailed findings

##### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /channels/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

##### 2. [LOW] Input reflected in search input value attr - fully entity-encoded on retest (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://discord.com/search reflects the token inside the VISIBLE search <input value="...">. RETEST 2026-09-25 raw-char matrix: " -> &quot;, ' -> &#x27;, > -> &gt; (all entity-encoded inside the double-quoted value attr); </script> and onfocus payloads 404-page (no reflection). No attribute breakout; downgraded medium -> low. Note discordapp.com itself is a redirect alias to discord.com (report kept under the listed domain).

##### 3. [LOW] Input reflected in search input value attr - fully entity-encoded on retest (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://discord.com/search reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

##### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://discord.com/s reflects input verbatim in body context; encoding boundary not confirmed.

##### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://discord.com/results reflects input verbatim in body context; encoding boundary not confirmed.

##### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

##### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://discord.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://discord.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/link reflects input verbatim in body context; encoding boundary not confirmed.

##### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/out reflects input verbatim in body context; encoding boundary not confirmed.

##### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/u reflects input verbatim in body context; encoding boundary not confirmed.

##### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/share reflects input verbatim in body context; encoding boundary not confirmed.

##### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://discord.com/s reflects input verbatim in body context; encoding boundary not confirmed.

##### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://discord.com/results reflects input verbatim in body context; encoding boundary not confirmed.

##### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

##### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://discord.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://discord.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/link reflects input verbatim in body context; encoding boundary not confirmed.

##### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/out reflects input verbatim in body context; encoding boundary not confirmed.

##### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/u reflects input verbatim in body context; encoding boundary not confirmed.

##### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/share reflects input verbatim in body context; encoding boundary not confirmed.

##### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://discord.com/view reflects input verbatim in body context; encoding boundary not confirmed.

##### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://discord.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

##### 28. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: discordapp.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

##### 29. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://discord.com/

##### 30. [INFO] humans.txt exposed (team/contact enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://discord.com/humans.txt returned 200 (996 bytes) with a matching signature.

##### 31. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://discord.com/.well-known/security.txt returned 200 (247 bytes) with a matching signature.

##### 32. [INFO] OpenID configuration exposed (identity endpoints enumerable) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://discord.com/.well-known/openid-configuration returned 200 (499 bytes) with a matching signature.

| 33 | info | I27 | Full request URL reflected URL-encoded in og:url meta on 404 pages (no breakout) | CWE-200 |

##### 33. [INFO] og:url meta reflection on 404 pages (I27)

- **CWE:** CWE-200
- **Detail:** 2026-09-25 deep-dive: https://discord.com/newage?redirect=X (404) reflects the full request URL in <meta property="og:url" content="https://discord.com/newage?redirect=X" />. Raw-char matrix: " -> a%22b, ' -> a%27b, > -> a%3Eb, <script> -> %3Cscript%3E - all remain percent-encoded inside the content attribute. No meta/attribute breakout; documented for completeness. (discord.com/login?return_to= is NOT reflected; /download?redirect= not reflected.)

###### Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

</details>

</details>
