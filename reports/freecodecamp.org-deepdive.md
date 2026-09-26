# Zero-Day Vulnerability Assessment Report
## freeCodeCamp.org Portal (www, api, forum, auth, gb.api, gb.web, status, news, coderadio, cdn subdomains)

| Item | Detail |
|---|---|
| Report ID | ZD-FCC-2026-09-26 |
| Assessment date | 25–26 September 2026 (all evidence timestamps UTC) |
| Target | https://www.freecodecamp.org plus the freecodecamp.org zone: api, forum, auth, gb.api, gb.web, status, news, coderadio, cdn subdomains |
| Stack | Gatsby 5.16.1 SPA (501 KB shell + 1.65 MB app bundle) on nginx behind Cloudflare; Next.js app on gb.web; Express API on gb.api; Discourse 2026.10.0-latest SaaS (CNAME hosted-by-discourse.com) forum; Auth0 tenant on custom domain auth.freecodecamp.org (Cloudflare-fronted auth0.com edge); UptimeRobot status page |
| Method | Unauthenticated active+passive: full-page capture, 1.65 MB JS bundle dig, 140-subdomain DoH (dns.google) inventory, WAF character matrix, CORS origin matrix, HTTP method matrix, open-redirect battery, SSTI probe, Auth0 OIDC discovery + dynamic-client-registration POST, GrowthBook API/console probing, forum JSON API probing, security-header audit across 8 origins, TLS/DNS |
| Classification | Confidential — prepared for responsible disclosure |
| Responsible-disclosure contact | freeCodeCamp security team via https://contribute.freecodecamp.org/security (security.txt PGP fingerprint F642B97E97BE935EE72C984F25CD692D1B27C70E, expires 2030-12-31) |

## 1. Executive Summary

On 25–26 September 2026 the freeCodeCamp.org website and its eleven probed subdomains were assessed unauthenticated and non-destructively. **19 findings: 2 Medium, 13 Low, 4 Informational.**

The most significant findings are:

1. The news application answers with **Access-Control-Allow-Origin: \* combined with Access-Control-Allow-Credentials: true** — captured live on 25 Sep on the `news.freecodecamp.org` origin (106 KB HTML) and re-confirmed on 26 Sep on the current redirect target `www.freecodecamp.org/news` (105,948 B), including on OPTIONS preflight (F-01).
2. The API origin **reflects the request Origin with credentials enabled** and simultaneously emits **duplicate, conflicting security headers** — one HSTS header carrying two max-age values, a CSP with two different `frame-ancestors` values, and `X-Frame-Options: DENY, SAMEORIGIN` (F-02, F-03).
3. The internal **GrowthBook feature-flag stack is publicly exposed**: an unauthenticated API returning the live feature definition JSON (with an SDK token in the URL path, `production: false` banner, a build dated 2023-10-30, no HSTS/CSP/XFO) plus its Next.js management web app at gb.web with zero security headers (F-04, F-05).
4. The Discourse forum exposes **per-user JSON profiles (badges, user_id, groups) and last-seen timestamps** unauthenticated, with a clean 404-JSON oracle for username enumeration (F-06).
5. Zone-wide hardening is inconsistent: permissive CSP (`http: https: data: blob: 'unsafe-inline' 'unsafe-eval'`), deprecated X-XSS-Protection, no Permissions-Policy on four origins, HSTS preload only on www/news, no HSTS on gb.\*, and a Cloudflare WAF that blocks only classic encoded XSS signatures (F-07–F-09, F-14, F-15).

All tests were unauthenticated; no forms were submitted and no state was changed beyond two harmless JSON POSTs (the Auth0 dynamic-registration probe and Algolia search attempts).

## 2. Scope and Environment

- **In scope:** www.freecodecamp.org (/, /news, /donate, /admin, /settings, /learn, /api, robots.txt, security.txt); api.freecodecamp.org (/, /signin); forum.freecodecamp.org (Discourse public JSON API); auth.freecodecamp.org (Auth0 tenant OIDC surface); gb.api / gb.web.freecodecamp.org (GrowthBook); status / cdn / coderadio / learn / blog subdomains; DNS zone via DoH; TLS.
- **Out of scope:** authenticated user flows, session-scoped curriculum endpoints, the GitHub organization, WebSocket channels, CDN asset-integrity audits, DoS testing.
- **Tooling:** Node 24 built-in fetch harness (`work/fcc2/01–18` scripts, `redirect: 'manual'`, status/length/headers recorded to JSON), manual header/DNS/bundle inspection, DoH via dns.google.
- **Stack behavior note:** www is a Gatsby SPA — unknown paths return the full 501 KB app shell (soft-200/soft-404); the Cloudflare edge WAF inspects query strings and returns its stock "Attention Required!" 403 page for classic encoded XSS signatures; the forum is SaaS-hosted (CNAME to hosted-by-discourse.com) so many Discourse controls sit with the provider.

## 3. Findings

### F-01 — CORS wildcard + credentials on the news application (ACAO:* with ACAC:true)
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N, 4.9) — CWE-942**

The news app returns `Access-Control-Allow-Origin: *` **and** `Access-Control-Allow-Credentials: true` on the same response. The CORS specification forbids this combination (a wildcard must not be honored with credentials), so strict modern browsers drop credentialed cross-origin reads — but permissive and legacy clients (older mobile WebViews, embedded frameworks, proxy layers) honor it, turning any same-zone or arbitrary-origin document into a cross-origin-readable surface. Captured on 25 Sep directly on `news.freecodecamp.org` (200, 105,955 B, on both GET and preflight) and re-confirmed on 26 Sep after the origin now 301-redirects to `www.freecodecamp.org/news` (200, 105,948 B), where the pair persists, with OPTIONS returning the ACAO as well.

```
25 Sep: GET https://news.freecodecamp.org/   (Origin: https://evil.com)
  -> 200 (105,955 B)  access-control-allow-origin: *  access-control-allow-credentials: true
26 Sep: GET https://www.freecodecamp.org/news  (Origin: https://evil.com)
  -> 200 (105,948 B)  access-control-allow-origin: *  access-control-allow-credentials: true
26 Sep: OPTIONS https://www.freecodecamp.org/news (Origin: https://evil.com)
  -> 200  access-control-allow-origin: *
```

**Remediation:** Pick one model: either emit `Access-Control-Allow-Origin: *` without credentials, or echo a validated allow-listed origin together with `Access-Control-Allow-Credentials: true`. Remove the pair from responses that never need cross-origin credentialed reads.

### F-02 — API origin reflects the request Origin with Access-Control-Allow-Credentials: true
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N, 6.3) — CWE-942**

`api.freecodecamp.org` answers every origin with an **echoed** `Access-Control-Allow-Origin` header set to the exact value of the incoming Origin, while also sending `Access-Control-Allow-Credentials: true`. This was confirmed live on the API root (404 JSON body still carries the CORS pair). An origin-echoing credentials-enabled CORS policy means any page an attacker controls can issue credentialed cross-origin requests to the API and read the responses in permissive clients — the classic setup for reading or mutating session-scoped API data cross-origin. It also differs from the wildcard on www (F-01), indicating two independently misconfigured CORS implementations in the same zone.

```
GET https://api.freecodecamp.org/   (Origin: https://www.freecodecamp.org)
  -> 404 (26 B)  body: {"error":"path not found"}
     access-control-allow-origin: https://www.freecodecamp.org   (echo of request Origin)
     access-control-allow-credentials: true
```

**Remediation:** Validate the Origin against an explicit allow-list of freecodecamp origins before echoing it, and enable `Access-Control-Allow-Credentials: true` only on endpoints that actually consume credentials; otherwise omit the header entirely.

### F-03 — Duplicate, conflicting security headers on the API origin (HSTS, CSP, X-Frame-Options)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N, 3.8) — CWE-1188**

The same API responses carry **two security-header chains at once**: one `Strict-Transport-Security` header containing two comma-joined directives (`max-age=300; includeSubDomains` **and** `max-age=31536000; includeSubDomains; preload`), a single CSP header containing two different `frame-ancestors` values (`'none'` followed by `'self'`), and `X-Frame-Options: DENY, SAMEORIGIN`. This is the fingerprint of two middlewares (edge + origin) each setting its own headers. Browsers differ in which conflicting value they apply (first-seen vs strictest), so the effective protection depends on client implementation, and the weaker `max-age=300` directive will be inherited by any parser that stops at the first directive.

```
strict-transport-security: max-age=300; includeSubDomains, max-age=31536000; includeSubDomains; preload
content-security-policy: frame-ancestors 'none', default-src 'self' http: https: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'
x-frame-options: DENY, SAMEORIGIN
```

**Remediation:** Assign each header to exactly one layer (recommend: set HSTS/CSP/XFO at the edge, strip duplicates at the origin), and re-audit the API origin until each header appears once with one unambiguous value.

### F-04 — Internal GrowthBook feature-flag API publicly exposed (gb.api.freecodecamp.org)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N, 3.8) — CWE-200**

`gb.api.freecodecamp.org` is an internal GrowthBook (feature-flag) API that is reachable unauthenticated with no HSTS, no CSP, no X-Frame-Options and `Access-Control-Allow-Origin: *`, fingerprinted as Express. The root returns its own service banner — `"production": false`, `config_source: "db"`, `email_enabled: false`, and a build SHA dated **2023-10-30** (three years old) — and `/api/features/sdk-szxzcLoVPQcu4WH` returns the complete live feature-definition JSON (3,610 B: feature names, default values, internal test flags such as `aa-test`), with the SDK authorization token placed in the URL path. Every other path answers 401 JSON, revealing that the entire subdomain is a token-gated API with one unauthenticated public token.

```
GET https://gb.api.freecodecamp.org/
  -> 200  x-powered-by: Express   (no HSTS / CSP / X-Frame-Options)
     {"name":"GrowthBook API","production":false,"api_host":"https://gb.api.freecodecamp.org",
      "app_origin":"https://gb.web.freecodecamp.org","config_source":"db","email_enabled":false,
      "build":{"sha":"f9349da702a37711118e1daf429f4475c6ea22ca","date":"2023-10-30..."}}
GET https://gb.api.freecodecamp.org/api/features/sdk-szxzcLoVPQcu4WH
  -> 200 (3,610 B)  access-control-allow-origin: *
     {"features":{"aa-test":{"defaultValue":false},"seasonal-alert":{"defaultValue":true},...}}
GET https://gb.api.freecodecamp.org/security.txt
  -> 401 {"status":401,"message":"No authorization token was found"}
```

**Remediation:** Move GrowthBook behind an authenticated admin origin (or at least add HSTS + a restrictive CSP/XFO and an auth check on all non-feature routes), rotate the SDK token out of the URL path into a header, and refresh the 2023 build.

### F-05 — GrowthBook management web app publicly exposed with zero security headers (gb.web.freecodecamp.org)
**Severity: Low (CVSS 3.1: AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N, 2.9) — CWE-311**

`gb.web.freecodecamp.org` serves the GrowthBook Next.js management application to the whole internet: a 2,485 B app shell with `X-Powered-By: Next.js`, a `/login` route, and `meta robots: noindex, nofollow` — the classic signature of an internal tool the team hopes nobody finds. The host sends **no** Strict-Transport-Security, **no** Content-Security-Policy, **no** X-Frame-Options and **no** Permissions-Policy, so the management console can be loaded over a hijackable plain-HTTP connection, framed by any origin (clickjacking of the login screen), and its scripts are unconstrained.

```
GET https://gb.web.freecodecamp.org/
  -> 200 (2,485 B)  x-powered-by: Next.js
     (no strict-transport-security / content-security-policy / x-frame-options / permissions-policy)
     <!DOCTYPE html>...<title>GrowthBook</title><meta name="robots" content="noindex, nofollow">
GET https://gb.web.freecodecamp.org/login  -> 404 (2,252 B GrowthBook page)
```

**Remediation:** Put the GrowthBook console behind SSO or an IP allow-list, and if it must stay public, add HSTS (with includeSubDomains/preload), a strict CSP, X-Frame-Options DENY and a Permissions-Policy baseline.

### F-06 — Unauthenticated forum user JSON profiles and last-seen disclosure (username enumeration oracle)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N, 3.8) — CWE-669**

The Discourse forum serves complete per-user JSON to unauthenticated clients: `/u/<username>.json` and `/users/<username>.json` return 200 with the user's internal `user_id`, granted badges with timestamps, group memberships, avatar templates, `profile_view_count` and trust-level flags. Separately, `/about.json` (17,366 B) lists top users including live **`last_seen_at` timestamps** (e.g. `2026-09-25T16:16:14Z`), letting an attacker build a presence/availability profile of forum members without any account. Unknown usernames return a clean 89 B 404 JSON error while known ones return 5 KB of data — a reliable enumeration oracle for discovering valid handles (staff, contributors, active students).

```
GET https://forum.freecodecamp.org/u/quincylarson.json
  -> 200 (5,187 B) {"user_badges":[{"id":27,"granted_at":"2016-05-09T20:33:34Z",...,"user_id":6},...]}
GET https://forum.freecodecamp.org/about.json
  -> 200 (17,366 B) {"users":[{"id":170865,"username":"ILM","last_seen_at":"2026-09-25T16:16:14.575Z"},...]}
GET https://forum.freecodecamp.org/u/zzqx9zrandomuser99.json
  -> 404 (89 B)  {"errors":["The requested URL or resource could not be found."],"error_type":"not_found"}
```

**Remediation:** Rate-limit and (for the /about.json aggregate) strip or round `last_seen_at` to a coarse bucket for anonymous clients; return a uniform 404 body for unknown handles to blunt enumeration.

### F-07 — Permissive site-wide CSP: http:/https:/data:/blob: plus unsafe-inline and unsafe-eval, no script-src/base-uri/form-action/object-src
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N, 3.8) — CWE-693**

The CSP on www and the news app is effectively a non-policy: `default-src 'self' http: https: data: blob: 'unsafe-inline' 'unsafe-eval'`. It permits **any** HTTPS or HTTP origin as a script source (mixed-content injections work), allows `data:` and `blob:` payloads (enabling inline exfiltration even against a 'self' script-src), and keeps both `'unsafe-inline'` and `'unsafe-eval'`. There is no explicit `script-src`, no `base-uri`, no `form-action` (form posts to arbitrary origins are allowed) and no `object-src`. A successful stored or reflected injection therefore runs with almost no CSP resistance, and `<base>`/form-hijack tricks are unblocked. The status subdomain ships the same permissive shape plus `upgrade-insecure-requests`, so the weakness is zone-wide.

```
content-security-policy: default-src 'self' http: https: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self';
   (served on www.freecodecamp.org, /news, and status.freecodecamp.org; 26 Sep 2026)
```

**Remediation:** Move to `script-src 'self'` (add nonces or hashes where needed), `base-uri 'self'`, `form-action 'self'`, `object-src 'none'`, and drop `http:`, `data:`, `blob:`, `'unsafe-inline'` and `'unsafe-eval'` in a staged rollout.

### F-08 — Deprecated X-XSS-Protection: 1; mode=block still emitted
**Severity: Low (CVSS 3.1: AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N, 2.9) — CWE-1188**

Both www and the news app still send `X-XSS-Protection: 1; mode=block`, a header deprecated in 2016 (and removed from Chrome in v56's spec lineage). Re-enabling the legacy XSS auditor is widely regarded as a net-negative: it introduces a non-standard, engine-specific parsing context that has historically produced its own filter-bypass bugs. Its presence indicates the header set has not been audited since the modern era.

```
x-xss-protection: 1; mode=block     (www.freecodecamp.org and /news, 26 Sep 2026)
```

**Remediation:** Remove the header (or explicitly set `0`) on all origins; the CSP in F-07 is the modern control.

### F-09 — No Permissions-Policy on four origins while one subdomain sends a full one
**Severity: Low (CVSS 3.1: AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N, 2.9) — CWE-1188**

`www`, `news` (redirect target), `forum` and `api` send no Permissions-Policy at all, so browser capabilities (geolocation, camera, microphone, payment, fullscreen, etc.) are governed by defaults whenever a page from these origins is framed or runs capability-gated code — including on the clickjackable origins without XFO (see gb.web, F-05). The inconsistency is demonstrated within the same zone: `status.freecodecamp.org` does send a complete policy (`geolocation=(),midi=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()`), so the pattern exists but is only applied to one subdomain.

```
permissions-policy: geolocation=(),midi=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()
   (present on status.freecodecamp.org only; absent on www / news / forum / api / gb.*)
```

**Remediation:** Apply the status page's Permissions-Policy baseline (or stricter) to every first-party origin.

### F-10 — Internal filenames disclosed via Content-Disposition on HTML responses
**Severity: Low (CVSS 3.1: AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N, 2.9) — CWE-200**

HTML documents from the www origin carry `Content-Disposition: inline; filename="index.html"` on the home/donate pages and `filename="404.html"` on 404 responses. `Content-Disposition` with a filename is intended for downloads; emitting it on normal HTML pages leaks the server-side file naming (and the fact that a dedicated 404 template exists), aids fingerprinting of the web-server/SPA pipeline, and makes the HTML documents eligible for browser "save/download" handling quirks. The filename even changes with the status code (`index.html` → `404.html`), confirming template-level injection of the header.

```
GET https://www.freecodecamp.org/      -> 200  content-disposition: inline; filename="index.html"
GET https://www.freecodecamp.org/donate -> 200  content-disposition: inline; filename="index.html"
GET https://www.freecodecamp.org/admin  -> 404  content-disposition: inline; filename="404.html"
```

**Remediation:** Drop `Content-Disposition` from HTML responses (it is redundant for inline navigation) or normalize it to a single value independent of status code.

### F-11 — All HTTP methods return 200 with the full HTML body; no 405 and no Allow header
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N, 3.8) — CWE-20**

Every method probed against the SPA origin — OPTIONS, PUT, DELETE, PATCH (and HEAD) — returns **200 with the complete 501,171 B application shell**, with no `Allow` header and no 405 response anywhere (checked on `/` and `/news`). Mutating methods therefore receive the same payload as GET, which makes method-based filtering unreliable (a WAF or CDN rule keyed on method+status sees no anomaly) and lets arbitrary verbs carry/trigger the full client bundle — including its embedded configuration and keys (F-17) — to any caller.

```
OPTIONS https://www.freecodecamp.org/  -> 200 (501,171 B)  (no Allow header)
PUT     https://www.freecodecamp.org/  -> 200 (501,171 B)
DELETE  https://www.freecodecamp.org/  -> 200 (501,171 B)
PATCH   https://www.freecodecamp.org/  -> 200 (501,171 B)
OPTIONS https://www.freecodecamp.org/news -> 200 (105,955 B)
```

**Remediation:** Return 405 with an accurate `Allow: GET, HEAD` for verbs the origin does not implement, at the edge or in the SPA server.

### F-12 — Inconsistent soft-200/404 shell: identical 501 KB app payload on 200 and 404 routes
**Severity: Low (CVSS 3.1: AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N, 2.9) — CWE-209**

The Gatsby origin returns the full application shell for essentially every path: real routes such as `/donate` and `/settings` return 200, while `/admin`, `/curriculum`, `/graphql` and `/api` return **404 — with the same ~501,179 B full HTML payload**, not a bare error page. Error responses therefore ship the entire client application (JS bundle references, embedded public config, third-party keys) to every 404, and status-code logic differs route-by-route for visually identical pages, which hampers monitoring/CDN error detection and exposes the app surface on requests that should terminate at an error.

```
/donate     -> 200 (501,177 B)
/settings   -> 200 (501,179 B)
/admin      -> 404 (501,179 B)
/curriculum -> 404 (501,179 B)
/graphql    -> 404 (501,179 B)
/api        -> 404 (501,179 B)   (separately: /api/ -> 301 -> /api)
```

**Remediation:** Serve a minimal error document (or a distinct lightweight 404 shell) for unknown paths so error responses do not carry the full application bundle and config, and align status codes for SPA routes that exist client-side.

### F-13 — /api self-redirect, bare JSON 404 root, and a cross-subdomain PKCE code-verifier cookie
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N, 3.8) — CWE-614**

Three related API-origin quirks: (1) `https://www.freecodecamp.org/api/` 301-redirects to `/api`, which then 404s into the app shell — a trailing-slash self-redirect pair that can loop in clients that normalize URLs; (2) the real API root `api.freecodecamp.org/` returns a bare 26 B `{"error":"path not found"}` with no Content-Type nuance or versioning, confirming a live but undocumented API origin; (3) `api.freecodecamp.org/signin` initiates Auth0 OAuth2 **PKCE** (code_challenge S256 + opaque state) against the custom tenant `auth.freecodecamp.org` and stores the `oauth2-code-verifier` in a cookie scoped to **Domain=.freecodecamp.org** — i.e. the PKCE secret is visible to every subdomain in the zone (forum, gb.*, status, cdn), widening the blast radius if any subdomain is ever compromised (XSS or subdomain takeover). The cookie is correctly HttpOnly/Secure/SameSite=Lax.

```
https://www.freecodecamp.org/api/      -> 301 Location: /api        (then 404 app shell)
https://api.freecodecamp.org/          -> 404 (26 B) {"error":"path not found"}
https://api.freecodecamp.org/signin    -> 302 https://auth.freecodecamp.org/authorize?response_type=code
                                       &client_id=aUDv9jVqTfxBRE1l60NA5Af7yTCGE4cy
                                       &redirect_uri=https%3A%2F%2Fapi.freecodecamp.org%2Fauth%2Fauth0%2Fcallback
                                       &code_challenge=<S256>&code_challenge_method=S256&state=<opaque>
set-cookie: oauth2-code-verifier=<secret>; Domain=.freecodecamp.org; Path=/; HttpOnly; Secure; SameSite=Lax
```

**Remediation:** Scope the verifier cookie to the `api` host only, return a versioned JSON 404 with proper Content-Type from the API origin, and resolve the /api/ → /api trailing-slash round-trip.

### F-14 — HSTS policy is inconsistent across the zone (preload only on www/news; none on gb.*; no includeSubDomains on forum)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N, 3.8) — CWE-319**

HSTS coverage varies by origin: `www` and the news pages send `max-age=31536000; includeSubDomains; preload`; the forum sends only `max-age=31536000` (no includeSubDomains, no preload); `gb.api` and `gb.web` send **no HSTS at all**; and the first plaintext `http://www.freecodecamp.org` hop is a bare 301 with no HSTS header to bootstrap the policy. Every non-preloaded subdomain (forum, gb.*, status, cdn, coderadio) therefore remains reachable over a hijackable plain-HTTP connection on first visit, and any future dangling subdomain (F-19) would be equally exposed.

```
www / news : strict-transport-security: max-age=31536000; includeSubDomains; preload
forum      : strict-transport-security: max-age=31536000
gb.api, gb.web: (absent)
http://www.freecodecamp.org/ -> 301 https://www.freecodecamp.org/   (no HSTS on the cleartext response)
```

**Remediation:** Standardize on `max-age=63072000; includeSubDomains; preload` across all subdomains (after verifying each responds to the preload checklist) and emit HSTS on the initial 301 response.

### F-15 — Cloudflare WAF blocks only classic encoded XSS signatures; single-character and word probes pass with 200
**Severity: Low (CVSS 3.1: AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N, 2.9) — CWE-20**

The Cloudflare edge on www inspects the query string and returns its stock "Attention Required!" 403 page (4,553 B) for classic encoded XSS signatures — `<script>alert(1)</script>`, `<svg onload=...>` and `" onerror="` — while **every** single raw character probe (`<`, `>`, `"`, `'`, backtick, `&`, `;`, `{`, `$`, `%`, space) and every word probe (`script`, `img`, `svg`, `lt`) passes with 200 and the full 501,171 B shell. Detection is thus signature-shape-dependent: minor encoding or splitting variations fall through to the origin, and the stock Cloudflare 403 page (with NEL reporting metadata) confirms WAF identity and rule firing to any probe. No payload was reflected by the SPA, so the finding is about the detection boundary and information disclosure rather than a confirmed bypass.

```
?q=%3Cscript%3Ealert(1)%3C/script%3E -> 403 (4,553 B) "Attention Required! | Cloudflare"
?q=%3Csvg%20onload=alert(1)%3E       -> 403 (4,553 B)
?q=%22%20onerror=%22alert(1)%22      -> 403 (4,553 B)
?q=%3C / %3E / %22 / %27 / %60 / %26 / %3B / %7B / %24 / %25 / %20  -> 200 (501,171 B) each
?q=script / img / svg / lt          -> 200 (501,171 B)
```

**Remediation:** Normalize the WAF rule set (detect on decoded content, not signature shape), serve a custom 403 that does not advertise the WAF vendor, and keep origin-side output encoding as the primary defense (the WAF is only a first layer).

### F-16 — Auth0 tenant: dynamic client registration endpoint exists (disabled, mechanism disclosed); legacy implicit flow still advertised
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N, 2.9) — CWE-326**

The custom Auth0 tenant `auth.freecodecamp.org` (Cloudflare-fronted `freecodecamp-cd-*.edge.tenants.auth0.com`) publishes full OIDC discovery. A live POST to the advertised `registration_endpoint` (`/oidc/register`) returns a structured 400 — `{"statusCode":400,"error":"Bad Request","message":"dynamic client registration is disabled"}` — confirming the RFC 7591 mechanism is built in and currently switched off (if enabled in the future, any party could register an OAuth client with an attacker redirect_uri against the production tenant). The same discovery document still lists legacy **implicit-flow** response types (`token`, `id_token`, `code token`, `token id_token`) alongside PKCE, and the supported-scope list includes `address` and `phone` — legacy options worth pruning from a modern tenant.

```
GET https://auth.freecodecamp.org/.well-known/openid-configuration
  "registration_endpoint":"https://auth.freecodecamp.org/oidc/register"
  "response_types_supported":["code","token","id_token","code token","token id_token","code id_token","code token id_token"]
POST https://auth.freecodecamp.org/oidc/register
  {"client_name":"zzq-probe","redirect_uris":["https://zzqx.test/cb"]}
  -> 400 {"statusCode":400,"error":"Bad Request","message":"dynamic client registration is disabled"}
```

**Remediation:** Remove the implicit-flow response types from the tenant configuration and keep dynamic client registration disabled (or gate it with tenant-level client validation) since the PKCE authorization-code flow is already in use.

### F-17 — Public client configuration and JS bundle expose the full third-party credential map
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N, 2.9) — CWE-200**

The site ships a public configuration object (also embedded verbatim in the 1.65 MB application bundle) that enumerates the entire third-party integration surface: Algolia App ID `QMJYL5WYTI` with search key `f91afff73d62604d4df9ae9046e8ca23`; a **live-mode** Stripe publishable key `pk_live_E6Z6xPM8pEsJziHW905zpAvF`; PayPal and Patreon OAuth client IDs; the GrowthBook SDK URL with its embedded token (F-04); and the deployment version hash `5c1ffbcc-20260921-1613`. Publishable/client IDs are public by design, but the concentration gives an attacker a ready-made map for targeted abuse (Algolia index discovery, Stripe payment-intent flow probing, OAuth client replay) and ties deployments to exact build hashes.

```
public config (served to all clients; also in app-76f3f911c745a265f36a.js, 1,650,068 B):
algoliaAppId: "QMJYL5WYTI"      algoliaAPIKey: "f91afff73d62604d4df9ae9046e8ca23"
stripePublicKey: "pk_live_E6Z6xPM8pEsJziHW905zpAvF"
paypalClientId: "Adg-W5qhw7qzirIbuMDiP4FWehU12uov9eABbtKYcMqx51OEnebbZ8Ltfop7d8u_Wdef4PuW5E_VhMpd"
patreonClientId: "PGqD1Y437poaGFek8YDwa4gTdUPZV72lkjzwozVNMPzzRhR7D4fQq0i85InlZCK9"
growthbookUri: "https://gb.api.freecodecamp.org/api/features/sdk-szxzcLoVPQcu4WH"
deploymentVersion: "5c1ffbcc-20260921-1613"
```

**Remediation:** Restrict the Algolia search key to the minimum indexes/ACLs it needs, keep the Stripe key in live-mode-only usage, and consider serving the config via a same-origin endpoint with per-key scoping rather than a static global object.

### F-18 — Discourse version disclosure on the forum (2026.10.0-latest, SaaS-hosted)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N, 2.9) — CWE-204**

Every forum 404 page carries `<meta name="generator" content="Discourse 2026.10.0-latest">` and the forum CNAMEs to `freecodecamp.hosted-by-discourse.com` (184.105.99.106, Discourse SaaS). The exact version string lets an attacker match published Discourse advisories to the running build without further probing. Because the instance is SaaS-hosted, the disclosure also signals that patch cadence is the provider's responsibility — but the version banner itself remains fully suppressible in the site configuration.

```
HTTP/2 404  (any unknown forum path)
<meta name="generator" content="Discourse 2026.10.0-latest - http...">
DNS: forum.freecodecamp.org. 5 CNAME freecodecamp.hosted-by-discourse.com. (184.105.99.106)
```

**Remediation:** Set the Discourse `version` meta generator to a generic value (or remove it) in the site configuration; keep the exact version for internal use only.

### F-19 — Dangling and legacy subdomains in the zone (help, docs, api-v2, legacy = NXDOMAIN; blog/learn = redirect hosts)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N, 2.9) — CWE-200**

DoH inventory of the zone (140 candidate names) shows four service names — `help.`, `docs.`, `api-v2.`, `legacy.` — returning **NXDOMAIN with no A/CNAME/NS records**, i.e. retired-but-still-meaningful service names that are takeover candidates if re-created pointing at infrastructure not owned by the team (no parking CNAMEs were found on any of the four). Meanwhile `blog.` 301-redirects to `/news/` (nginx), `learn.` 302-redirects to `/learn/`, `status.` serves a public 27,901 B status page and `coderadio.`/`cdn.` serve small public pages — a mixed fleet of redirect hosts, a public monitoring page and an asset origin, all part of the same zone.

```
help. / docs. / api-v2. / legacy. freecodecamp.org -> NXDOMAIN (no A, CNAME or NS records)
blog.  -> 301 https://www.freecodecamp.org/news/     (nginx)
learn. -> 302 https://www.freecodecamp.org/learn/
status. -> 200 (27,901 B) public status page
coderadio. -> 200 (3,489 B)   cdn. -> 200 (2,601 B)
```

**Remediation:** Either remove the dangling names or point them at a controlled origin (parking page/404), and add them to the HSTS preload list once they resolve (F-14).

## 4. Blocked Escalation Attempts

| Attempt | Result |
|---|---|
| Auth0 dynamic client registration (POST /oidc/register) | 400 — "dynamic client registration is disabled" (would be a Medium if enabled) |
| Open-redirect battery (?redirect=/next=/returnTo=/url=/r=/target=/continue) on www | All 200 into the soft-200 shell, no Location header — client-side SPA routing only |
| SSTI battery (?q=/param=/id=/name= with {{7*7}}, ${7*7}, %{7*7}) | No reflection of the computed value; "49" matches in the shell are static content |
| Classic XSS via query on www (script/onerror/svg/onload signatures) | 403 Cloudflare WAF (signature-based); single chars/words pass but are not reflected |
| /graphql, /admin, /curriculum on www | 404 app shell — no GraphQL endpoint exposed |
| Algolia index search with the public search key (news_articles, articles, news) | 404 "Path not supported" — endpoint shape mismatch; key accepted by the Algolia edge |
| .git/ and .env on www | 403 via Cloudflare (hidden, not absent) |
| Forum staff/health/privacy endpoints (/about/staff.json, /about/health, /t.json) | 404 (only the /about.json aggregate is open) |
| Other GrowthBook API paths (e.g. /security.txt, arbitrary routes) | 401 "No authorization token was found" — token-gated, no unauthenticated data |
| news.freecodecamp.org direct origin (the 25 Sep ACAO:*+ACAC:true host) | Now 301 to www/news — finding re-confirmed at the redirect target |

## 5. Remediation Priorities

1. **Fix the two CORS misconfigurations** — wildcard+credentials on the news app (F-01) and origin-echo+credentials on the API (F-02): one allow-listed model zone-wide.
2. **De-duplicate the API origin's security headers** so HSTS, CSP and X-Frame-Options each appear once with a single value (F-03).
3. **Lock down the GrowthBook pair** — authentication or IP allow-list for gb.web, auth check on all gb.api routes beyond the feature endpoint, HSTS/CSP/XFO added, SDK token out of the URL, 2023 build refreshed (F-04, F-05).
4. **Gate forum identity data** — coarse `last_seen_at` buckets and uniform 404 bodies for anonymous clients (F-06).
5. **Tighten the CSP zone-wide** — script-src 'self', base-uri, form-action, object-src 'none'; drop http:/data:/blob:/unsafe-inline/unsafe-eval (F-07).
6. **Modernize headers** — remove X-XSS-Protection (F-08), apply the Permissions-Policy baseline to all origins (F-09), and drop Content-Disposition from HTML (F-10).
7. **Standardize HSTS** — preload + includeSubDomains on every subdomain, including the initial cleartext 301 hop (F-14).
8. **Harden HTTP semantics** — 405 + Allow for unimplemented verbs (F-11), minimal error documents instead of the full app shell on 404 (F-12), and fix the /api/ self-redirect plus the cross-subdomain PKCE cookie scope (F-13).
9. **Normalize the WAF** — decoded-content detection, custom non-vendor 403 (F-15).
10. **Prune the tenant and zone** — remove implicit flow from the Auth0 tenant (F-16), scope the Algolia key (F-17), suppress the Discourse version banner (F-18), and resolve the four dangling subdomains (F-19).

## 6. Disclosure

freeCodeCamp publishes a valid `security.txt` (found via `/security.txt` → `/.well-known/security.txt` on www and api): Contact https://contribute.freecodecamp.org/security (the "Reporting a Vulnerability" page), Encryption key PGP fingerprint `F642B97E97BE935EE72C984F25CD692D1B27C70E` (published at keys.openpgp.org), Policy https://contribute.freecodecamp.org/security, valid until 2030-12-31, with a security hall-of-fame link for contributors. The forum and both GrowthBook hosts do not carry a security.txt copy (F-19 family). Recommended disclosure path: encrypted submission via the contribute.freecodecamp.org security page, with the findings grouped as in this report (F-01…F-19).

*End of report — ZD-FCC-2026-09-26.*
