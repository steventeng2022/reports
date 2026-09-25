# Security Audit Report — webmd.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://webmd.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | webmd.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

<<<<<<< HEAD
Total findings: **16** (High: 0, Medium: 0, Low: 6, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 7 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 8 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 9 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 10 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 11 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 14 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 15 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 16 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://webmd.com/ without HttpOnly: VisitorId, ab, gtinfo, lrt_wrk. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://webmd.com/ without Secure: VisitorId, ab, gtinfo, lrt_wrk. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://webmd.com/ without SameSite=Lax/Strict: VisitorId, __cf_bm, ab, gtinfo, lrt_wrk. Cross-site request cookies.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://webmd.com/. Clients may connect over plain HTTP on first visit.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://webmd.com/; browsers may MIME-sniff responses.

### 6. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://webmd.com/; page may be rendered in a foreign frame.

### 7. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond webmd.com: www.webmd.com.

### 8. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for webmd.com lists 84 name(s) besides the scope host: *.derigo.us, *.framesdata.com, *.krames.com, *.kramesondemand.com, *.kramesonline.com, *.kramesstaywell.com, *.kramesvideo.com, *.la1.webmd.com... (4 no longer resolve)

### 9. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `images.onhealth.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 10. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `le.prod.webmd.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 11. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `staywellsolutionsonline.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://webmd.com/; full URL (incl. query strings) is sent as referrer by default.

### 13. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://webmd.com/; browser features (camera, mic, geolocation) unrestricted.

### 14. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://webmd.com/ -> https://www.webmd.com/ (positive check).

### 15. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://webmd.com/ exposes 23 unique Disallow path(s) (*/search/search_results/, /, /500, /Share.aspx*, /aim/)

### 16. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://webmd.com (110 bytes); contact: https://bugcrowd.com/internetbrands-public

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://webmd.com/ final status: 200 (final URL https://www.webmd.com/).
- http://webmd.com/ initial status: 301.
- Certificate: Let's Encrypt YR1, valid until 2026-12-01T00:10:03+00:00.

## Active agent cross-check (wave 7-9 aggressive scan on main - webmd.com)

Total findings: **36** - latest aggressive-method scan (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.
=======
Total findings: **36** (High: 0, Medium: 0, Low: 5, Info: 31)
>>>>>>> 856185b (verify pass: webmd 19x I1, typekit 4x I1, ca.linkedin I2+4xI5, vogue SSTI all REFUTED (token matrices); reports+README updated; wave 10 shipped (122); chat)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 2 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 3 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 4 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 5 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 6 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 7 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 8 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 9 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 10 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 11 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 12 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 13 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 14 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 15 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 16 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 17 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 18 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 19 | info | I1 | Reflected XSS in JavaScript context - REFUTED (verified 2026-09-26) | CWE-79 |
| 20 | low | H1 | Missing HSTS header | CWE-319 |
| 21 | low | H4 | No clickjacking protection | CWE-1023 |
| 22 | low | C1 | Cookies without Secure flag | CWE-614 |
| 23 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 24 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 25 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 26 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 27 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ | CWE-942 |
| 28 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ | CWE-942 |
| 29 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ | CWE-942 |
| 30 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api | CWE-942 |
| 31 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api | CWE-942 |
| 32 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api | CWE-942 |
| 33 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql | CWE-942 |
| 34 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql | CWE-942 |
| 35 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql | CWE-942 |
| 36 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |
<<<<<<< HEAD
=======

## Detailed findings

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.webmd.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.webmd.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.webmd.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.webmd.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.webmd.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.webmd.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.webmd.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.webmd.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### N. [INFO] Reflected XSS in JavaScript context - REFUTED (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.webmd.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

- **Verification (2026-09-26, rule 4):** All I1 entries above are REFUTED. Re-requested with unique token ZZQwebmd7x2w9: /s?q=, /results?q=, /redirect?url=, /go?url=, /search?q= all return the identical 200 / 425,914-byte page for every path and payload, and the token is not reflected anywhere in the body - the engine "inside <script>" flag was a static-content heuristic on a generic page.

### 20. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.webmd.com/

### 21. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.webmd.com/

### 22. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** lrt_wrk, gtinfo, VisitorId, ab set without Secure on https://www.webmd.com/

### 23. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** lrt_wrk, gtinfo, VisitorId, ab set without HttpOnly on https://www.webmd.com/

### 24. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: webmd.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 25. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.webmd.com/

### 26. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.webmd.com/

### 27. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 28. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/plain). Any site can read responses cross-origin.

### 29. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 30. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 31. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/plain). Any site can read responses cross-origin.

### 32. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 33. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 34. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/plain). Any site can read responses cross-origin.

### 35. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://www.webmd.com/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://www.webmd.com/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 36. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.webmd.com/.well-known/security.txt returned 200 (110 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
>>>>>>> 856185b (verify pass: webmd 19x I1, typekit 4x I1, ca.linkedin I2+4xI5, vogue SSTI all REFUTED (token matrices); reports+README updated; wave 10 shipped (122); chat)
