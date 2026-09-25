# Security Audit Report — infusionsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://infusionsoft.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | infusionsoft.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 4 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 7 | info | H2c | HSTS not preloaded | CWE-319 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 11 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 12 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 13 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://infusionsoft.com/ without HttpOnly: XSRF-TOKEN. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://infusionsoft.com/ without Secure: XSRF-TOKEN, laravel_session. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://infusionsoft.com/; no defense-in-depth against XSS/content injection.

### 4. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://infusionsoft.com/; browsers may MIME-sniff responses.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for infusionsoft.com lists 1 name(s) besides the scope host: *.infusionsoft.com

### 6. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` does not cover subdomains.

### 7. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000` lacks the preload directive.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://infusionsoft.com/; full URL (incl. query strings) is sent as referrer by default.

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://infusionsoft.com/; browser features (camera, mic, geolocation) unrestricted.

### 10. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://infusionsoft.com/ -> https://www.infusionsoft.com/ (positive check).

### 11. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://infusionsoft.com/ exposes 7 unique Disallow path(s) (/, /infusionsoft/resources/thank-you, /infusionsoft/resources/thank-you/*, /infusionsoft/subscribe/thank-you, /resources/thank-you) and 1 sitemap reference(s)

### 12. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on infusionsoft.com.

### 13. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://infusionsoft.com/ redirects to https://keap.com.

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://infusionsoft.com/ final status: 200 (final URL https://keap.com).
- http://infusionsoft.com/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-11-05T18:14:54+00:00.

## Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before PR #1 was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 41 findings: 0 high, 1 medium, 35 low, 5 info</summary>

### Security Audit Report — infusionsoft.com

#### Scope and authorization

| Item | Value |
|---|---|
| Target | https://infusionsoft.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | infusionsoft.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

#### Summary

Total findings: **41** (High: 0, Medium: 1, Low: 35, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
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
| 32 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 33 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 34 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 35 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 36 | info | T2 | TLS certificate expiring within 42 days | CWE-295 |
| 37 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 38 | info | H5 | Missing Referrer-Policy | CWE-200 |

#### Detailed findings

##### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.infusionsoft.com/

##### 2. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.infusionsoft.com/

##### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** XSRF-TOKEN, laravel_session set without Secure on https://www.infusionsoft.com/

##### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** XSRF-TOKEN set without HttpOnly on https://www.infusionsoft.com/

##### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.infusionsoft.com/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/s reflects input verbatim in body context; encoding boundary not confirmed.

##### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/ reflects input verbatim in body context; encoding boundary not confirmed.

##### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/results reflects input verbatim in body context; encoding boundary not confirmed.

##### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

##### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.infusionsoft.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.infusionsoft.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/link reflects input verbatim in body context; encoding boundary not confirmed.

##### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/out reflects input verbatim in body context; encoding boundary not confirmed.

##### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/u reflects input verbatim in body context; encoding boundary not confirmed.

##### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/share reflects input verbatim in body context; encoding boundary not confirmed.

##### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.infusionsoft.com/search reflects input verbatim in body context; encoding boundary not confirmed.

##### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/s reflects input verbatim in body context; encoding boundary not confirmed.

##### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/ reflects input verbatim in body context; encoding boundary not confirmed.

##### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/results reflects input verbatim in body context; encoding boundary not confirmed.

##### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

##### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.infusionsoft.com/go reflects input verbatim in body context; encoding boundary not confirmed.

##### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.infusionsoft.com/r reflects input verbatim in body context; encoding boundary not confirmed.

##### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/link reflects input verbatim in body context; encoding boundary not confirmed.

##### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/out reflects input verbatim in body context; encoding boundary not confirmed.

##### 31. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/u reflects input verbatim in body context; encoding boundary not confirmed.

##### 32. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/share reflects input verbatim in body context; encoding boundary not confirmed.

##### 33. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/view reflects input verbatim in body context; encoding boundary not confirmed.

##### 34. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.infusionsoft.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

##### 35. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: infusionsoft.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

##### 36. [INFO] TLS certificate expiring within 42 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.infusionsoft.com (CN=infusionsoft.com) valid_to Nov  5 18:14:54 2026 GMT.

##### 37. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.infusionsoft.com/

##### 38. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.infusionsoft.com/

| 39 | medium | I31 | Pre-auth param-preserving meta-refresh redirector chain (infusionsoft -> keap -> accounts.infusionsoft) | CWE-668 |
| 40 | info | I32 | Cloudflare WAF: full <script>/</title> sequences 403 in query, individual special chars pass + reflect URL-encoded | CWE-200 |
| 41 | info | I33 | keap.com JSON-LD "url" property reflects request URL (URL-encoded, no breakout) | CWE-200 |

#### Detailed findings (deep-dive addendum 2026-09-25)

##### 39. [MEDIUM] Pre-auth param-preserving meta-refresh redirector chain (I31)

- **CWE:** CWE-668
- **Detail:** Verified 2026-09-25: ANY query on the www.infusionsoft.com apex is preserved verbatim in a 301 meta-refresh to keap.com - e.g. https://www.infusionsoft.com?cb=X -> <meta http-equiv="refresh" content="0;url='https://keap.com?cb=X'" /> with the X also reflected (URL-encoded) in the 301 page <title> ("Redirecting to https://keap.com?cb=X"). The same pattern exists at /keap/login?redirect=X -> keap.com/keap/login?redirect=X. Third hop: https://keap.com/login?redirect=X -> 301 meta-refresh -> https://accounts.infusionsoft.com/?redirect=X (parameter preserved into the auth host). The chain moves arbitrary parameters from the marketing apex into the login/account host before authentication. If accounts.infusionsoft.com performs an open redirect on /?redirect= post-login (auth-state re-test pending), this becomes a pre-auth phishing chain. File as medium until the post-login hop is confirmed.

##### 40. [INFO] Cloudflare WAF behavior on the redirector (I32)

- **CWE:** CWE-200
- **Detail:** Queries containing full <script> or </title> sequences return 403 (Cloudflare "Attention Required!"), while individual special characters - < (cb=%3c), >, space, newline, ", backslash, = - all pass and are reflected URL-ENCODed in the <title> (a%22b stays a%22b; %3C stays %3C). The encoding neutralizes the reflected chars; the WAF only blocks multi-char payload signatures.

##### 41. [INFO] keap.com JSON-LD url reflection (I33)

- **CWE:** CWE-200
- **Detail:** https://keap.com?cb=X (200, 290KB) reflects the request URL in the JSON-LD block: "url":"http://keap.com/?cb=X" inside a <script type="application/ld+json">. Quote/backslash/newline tests (a%22b, a%5cb, a%0ab) all remain percent-encoded inside the JSON string - no string breakout.

#### Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

</details>
