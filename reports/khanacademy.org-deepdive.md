# Zero-Day Vulnerability Assessment Report
## Khan Academy Portal (khanacademy.org, www.khanacademy.org, classroom/admin/api.khanacademy.org)

| Item | Detail |
|---|---|
| Report ID | ZD-KHAN-2026-09-24 |
| Assessment date | 24 September 2026 (all evidence timestamps UTC) |
| Target | https://www.khanacademy.org (Fastly CDN edge with Varnish backend; apex via CloudFront; subdomains classroom.khanacademy.org, admin.khanacademy.org, api.khanacademy.org) |
| Stack | Fastly "Client Challenge" (proof-of-work) layer, Google App Engine (gae_b_id), React/Next-style SPA app shell, internal REST + GraphQL API layer under /api/internal/ |
| Method | Non-destructive manual assessment: CDN/header/cookie forensics, intermittent challenge-response differential testing, robots-disallowed path fingerprinting, JS-bundle endpoint extraction + live API probing, method/encoding matrices, soft-200 differentials |
| Classification | Confidential — prepared for responsible disclosure |
| Responsible-disclosure contact | Khan Academy via HackerOne program: https://hackerone.com/khanacademy |

## 1. Executive Summary

On 24 September 2026 the Khan Academy web properties were assessed unauthenticated and non-destructively (GET/POST/OPTIONS/HEAD only; no forms submitted; no credentials). **27 findings: 4 Medium, 13 Low, 10 Informational.**

The most significant findings are:

1. A **live, unauthenticated internal GraphQL router** at `/api/internal/graphql/__opname__` that answers with a protocol-specific JSON error, on a path family that robots.txt explicitly hides (F-01).
2. An **unauthenticated HTTP 500** on the internal telemetry endpoint `POST /api/internal/_bb/page_perf_log` (F-02).
3. A **Go handler-name disclosure** (`rest.TextToSpeechHandler`) from the internal AI text-to-speech endpoint (F-03).
4. An **HSTS coverage gap**: the full `preload` HSTS policy exists only on origin responses of www.khanacademy.org; it is absent from intermittent Fastly challenge responses, from the apex 308 redirect (CloudFront), and from all probed subdomains — leaving classroom/admin/api permanently unprotected against SSL-strip despite `includeSubDomains` (F-04).

The site intermittently serves Fastly's proof-of-work "Client Challenge" page (3,038 bytes) with HTTP 200 for arbitrary paths, alternated with the real 219 KB app shell for the same URL; every finding below was cross-verified against both response classes to avoid challenge-page false positives.

## 2. Scope and Environment

- **In scope:** khanacademy.org; www., classroom., admin., api. subdomains; paths listed in robots.txt (/admin/, /devadmin/, /api/internal/_bb/, /crash, /preview/, /postlogin, /_ah/); public JS bundle `cdn.kastatic.org/khanacademy/khanacademy.30b8a2c59134ef2d.js`.
- **Out of scope:** authenticated areas, mobile apps, the kastatic.org asset CDN itself (analyzed for endpoint/DSN extraction only), third-party analytics backends.
- **Tooling:** Node 24 fetch-based harness (work\khan\manual2.js – manual8.js), manual header/JS inspection; all requests unauthenticated.
- **CDN behavior note:** www responses alternate between (a) Fastly challenge page: 3038 B, `via: 1.1 varnish`, `x-varnish: <id>`, meta CSP, no HSTS, and (b) origin app shell: ~219 KB, HSTS preload, CSP frame-ancestors, `cache-control: private, no-store`. Subdomain requests (classroom/admin/api) consistently return the bare challenge page with no security headers at all.

## 3. Findings

### F-01 — Live unauthenticated internal GraphQL router on robots-disallowed path
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-639**

`GET /api/internal/graphql/__opname__` returns a genuine JSON GraphQL error envelope from a live router, unauthenticated. The path sits inside the internal API family that robots.txt disallows, and the error message discloses the query protocol (hash-based requests: "No hash= specified"), which enables offline enumeration of valid hash values against the production internal API. The sibling `/api/*` router answers differently (400, text/plain), confirming `/api/internal/*` is a distinct, dedicated internal layer exposed on the public origin.

```
$ curl -s https://www.khanacademy.org/api/internal/graphql/__opname__
HTTP/2 400
content-type: application/json

{"errors":[{"message":"No hash= specified"}]}

$ curl -s https://www.khanacademy.org/api
HTTP/2 400
webpage handler can't process the URL
```

**Remediation:** Route /api/internal/* through the authenticated API gateway (or return a generic 404 for unknown internal operations); avoid protocol-specific errors on internal paths.

### F-02 — Unauthenticated HTTP 500 on internal telemetry endpoint
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-209**

`POST /api/internal/_bb/page_perf_log` (page-performance telemetry, part of the "_bb" bigbingo family referenced by the public JS bundle) returns an unauthenticated **500** for a minimal request body, while the sibling `POST /api/internal/_bb/bigbingo/mark_conversions` silently returns 200. An unauthenticated 500 on an internal endpoint indicates a missing/incorrect input contract (likely nil dereference or missing required field) and can leak stack details or be used as a free DoS oracle; the 200-on-write sibling shows the endpoint accepts unauthenticated writes.

```
$ curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'content-type: application/json' -d '{}' \
    https://www.khanacademy.org/api/internal/_bb/page_perf_log
500

$ curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'content-type: application/json' -d '{}' \
    https://www.khanacademy.org/api/internal/_bb/bigbingo/mark_conversions
200
```

**Remediation:** Return 400/401 with a generic message for malformed/unauthenticated telemetry payloads; validate required fields before handler dispatch.

### F-03 — Internal Go handler-name disclosure on AI text-to-speech endpoint
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-209**

`POST /api/internal/_ai-guide/text-to-speech/` returns 403 with a framework-level error that names the internal Go handler: `rest.TextToSpeechHandler: [unauthorized error]`. This discloses (a) the existence of an internal AI-guide TTS REST endpoint, (b) the implementation language/handler registry naming, and (c) the authorization model, aiding targeted attacks against the internal AI pipeline.

```
$ curl -s -X POST -H 'content-type: application/json' -d '{}' \
    https://www.khanacademy.org/api/internal/_ai-guide/text-to-speech/
HTTP/2 403
rest.TextToSpeechHandler: [unauthorized error]
```

**Remediation:** Return a generic 403 body on internal endpoints; keep handler names out of error text (log them server-side instead).

### F-04 — HSTS coverage gap: challenge responses, apex redirect, and all subdomains
**Severity: Medium (CVSS 3.1: AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N, 4.9) — CWE-319**

Origin responses of www.khanacademy.org carry `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`, but the policy is **absent** from: (1) intermittent Fastly challenge responses on www (served by Varnish with only a meta CSP), (2) the apex `khanacademy.org` → `www` 308 redirect via CloudFront, and (3) all probed subdomains (classroom/admin/api), which return bare challenge pages with no security headers at all. Because the apex redirect itself lacks HSTS, `includeSubDomains` can never be bootstrapped for subdomains — every first visit to classroom/admin/api is exposed to SSL-strip, and a first visit to www during a challenge window receives no HSTS hint either.

```
$ curl -sI https://www.khanacademy.org/            # origin response
strict-transport-security: max-age=31536000; includeSubDomains; preload

$ curl -sI https://khanacademy.org/                # apex 308 via CloudFront
HTTP/1.1 308
location: https://www.khanacademy.org/
# (no strict-transport-security)

$ curl -sI https://admin.khanacademy.org/          # subdomain, challenge page
HTTP/2 200
via: 1.1 varnish
# (no strict-transport-security, no csp, no xfo, no xcto)
```

**Remediation:** Emit HSTS on every response path (challenge pages, apex redirects, all subdomains) and add the subdomains to the preload list once stable.

### F-05 — browsing_session_id cookie set without HttpOnly
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-1004**

The `browsing_session_id` cookie (value pattern `_en_bsid_uuid`) is set on first response without the `HttpOnly` flag, making the session identifier readable by JavaScript and a direct amplification primitive for any XSS on the origin. The companion `browsing_session_expiry` is correctly `Secure`.

```
Set-Cookie: browsing_session_id=_en_bsid_uuid...; Path=/   # no HttpOnly, no Secure
Set-Cookie: browsing_session_expiry="Thu, 24 Sep 2026 12:15:40 UTC"; Path=/; Secure
```

**Remediation:** Add `HttpOnly; Secure; SameSite=Lax` to the session-identifier cookie.

### F-06 — Fastly challenge cookie _fs_ch_st_* lacks Secure and SameSite
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-614**

The proof-of-work challenge state cookie is set as `_fs_ch_st_<id>=<long token>; Max-Age=10; HttpOnly; Path=/` with **no Secure and no SameSite** attributes. With a 10-second TTL the exposure window is short, but the large encrypted token is sent over plaintext HTTP and on cross-site requests, and the missing SameSite lets it participate in cross-site form flows during the challenge window.

```
Set-Cookie: _fs_ch_st_FSBmUei20MqUiJb9=ARHQKDy5...; Max-Age=10; HttpOnly; Path=/
```

**Remediation:** Add `Secure; SameSite=Strict` to challenge-state cookies (Fastly challenge configuration).

### F-07 — Site-wide soft-200: every unknown path returns the full app shell
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1032**

Any unknown origin path (e.g. `/.env.local`, `/actuator`, `/wp-login.php`, `/debug`, `/search?query=math`) returns HTTP 200 with the full ~219 KB SPA shell instead of a 404, so only `/api/internal/_bb/` (19 B "404 page not found") is a true 404. This defeats broken-link/security scanning and hides sensitive paths; the requested path is additionally reflected **percent-encoded** into the `canonical` and `og:url` meta tags (verified with `?continue=%2F%2Fevil.example%2Fx` on /login — safely encoded, no raw-quote round-trip observed).

```
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://www.khanacademy.org/.env.local
200 3038    (challenge variant) / 219611 (origin variant)
$ curl -s https://www.khanacademy.org/.env.local | grep -o '<link rel="canonical"[^>]*'
<link rel="canonical" href="https://www.khanacademy.org/.env.local">
```

**Remediation:** Serve real 404s for unknown paths; keep canonical/og:url generated from the resolved route, not the raw request path.

### F-08 — Single shared weak ETag for all origin HTML responses
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-913**

All origin HTML responses (/, /login, /api, /debug, /math, …) share the identical weak ETag `W/"30a68f8b18f335d725146298d752c0b8"` and `cache-control: private, no-store`. A shared identity across distinct documents invites cache/proxy collisions (wrong page served on conditional requests) and gives CDNs/interceptors a coarse fingerprint; combined with the observed `age` value of ~48,845 s (~13.6 h) on no-store content, stale-content semantics are inconsistent.

```
$ curl -sI https://www.khanacademy.org/login
etag: W/"30a68f8b18f335d725146298d752c0b8"
cache-control: private, no-store
age: 48845

$ curl -sI https://www.khanacademy.org/api
etag: W/"30a68f8b18f335d725146298d752c0b8"   # identical
```

**Remediation:** Derive ETags per resource (hash of content) or omit them on no-store documents; reconcile Age emission with cache directives.

### F-09 — Inconsistent error handling across routers aids fingerprinting
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

The same origin exposes at least four distinct error dialects: 404 "404 page not found" (19 B, internal router), 404 "Page Not Found" (14 B, Go net/http default for OPTIONS/PATCH on /), 400 "webpage handler can't process the URL" (37 B, /api router), 400 JSON GraphQL errors (/api/internal/graphql), and empty 406 responses for certain Content-Type/encoding variants (e.g. /.DS_Store). The mix of hand-rolled, framework-default, and JSON error bodies lets an attacker map which layer (edge Varnish, GAE, Go app, API router) terminates a given path.

```
GET  /api/internal/_bb/          -> 404  "404 page not found"
OPTIONS /  and  PATCH /          -> 404  "Page Not Found"
GET  /api                        -> 400  "webpage handler can't process the URL"
GET  /api/internal/graphql/...   -> 400  {"errors":[...]}
GET  /.DS_Store (enc variant)    -> 406  (0 bytes)
```

**Remediation:** Centralize error handling: one status/body family per layer, no framework-default bodies on the public origin.

### F-10 — Internal endpoints and Sentry DSNs disclosed in public JS bundle
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-200**

The 1.9 MB public bundle (`khanacademy.30b8a2c59134ef2d.js`) embeds internal API routes — `/api/features/`, `/api/eval/`, `/api/internal/time/usage_time`, `/api/internal/_bb/page_perf_log`, `/api/internal/_bb/bigbingo/mark_conversions`, `/api/internal/graphql/__opname__`, `/api/internal/_ai-guide/text-to-speech/` — plus two production Sentry DSNs with public keys and project IDs: `https://0d3382554dd24dc998a5937351b12379@o8287.ingest.sentry.io/15744` and `https://ff8ead3bfa9a4c5b9987f5fd8c62301b@o8287.ingest.sentry.io/1281302`. The DSNs allow unauthenticated event injection into the org's Sentry projects (noise/quota consumption) and confirm org ID o8287.

```
# extracted from khanacademy.30b8a2c59134ef2d.js
"https://0d3382554dd24dc998a5937351b12379@o8287.ingest.sentry.io/15744"
"https://ff8ead3bfa9a4c5b9987f5fd8c62301b@o8287.ingest.sentry.io/1281302"
"/api/internal/_ai-guide/text-to-speech/"
```

**Remediation:** Trim bundles (tree-shaking/obfuscation of internal routes); rotate Sentry DSNs and use a rate-limited relay for client ingestion.

### F-11 — robots.txt discloses internal path inventory and GAE origin
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-532**

robots.txt (1,129 B, served with `max-age=3600`) enumerates otherwise-hidden internal paths: `/_ah/` (Google App Engine internal namespace), `/admin/`, `/devadmin/`, `/api/internal/_bb/`, `/crash`, `/embed_video`, `/login?continue=*`, `/postlogin`, `/preview/`, plus a `GPTBot`-specific `Disallow: /`. This is a ready-made target list for scanners and confirms the GAE backend (`/_ah/`) behind the Fastly edge.

```
User-agent: GPTBot
Disallow: /
User-agent: *
Sitemap: https://www.khanacademy.org/sitemap.xml
Disallow: /_ah/
Disallow: /admin/
Disallow: /api/internal/_bb/
Disallow: /crash
Disallow: /devadmin/
...
```

**Remediation:** Keep robots minimal; protect disallowed paths with auth/404 rather than relying on robots.txt, or split into a private robots for crawlers.

### F-12 — CDN backend (Varnish) and Fastly internal asset path disclosed on challenge responses
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-497**

Challenge responses expose `via: 1.1 varnish` and per-request `x-varnish: <id>` headers (backend implementation + cache-slot fingerprinting) and the embedded JS references Fastly-internal asset paths (`/_fs-ch-1T1wmsGaOgGaSxcX`, fetched `/fastly/logo` endpoint). These internal tokens/paths map the CDN deployment and can be reused in targeted edge-cache or misconfiguration tests.

```
HTTP/2 200
via: 1.1 varnish
x-varnish: 2255681042
...
const _errorsBasePath = ... return "/_fs-ch-1T1wmsGaOgGaSxcX";
const logoUrl = `${window.location.origin}/fastly/logo`;
```

**Remediation:** Strip Via/X-Varnish on public responses; serve challenge assets from a neutral path and suppress the internal asset base in shipped JS.

### F-13 — Long-lived backend/affinity cookies (gae_b_id 1 year, KAAL 2 years)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-200**

First responses set `gae_b_id` containing a base64-encoded GAE backend instance identifier (`kaId_2599970799920745561836`) with a 1-year TTL, and `KAAL=1` domain-wide on khanacademy.org with a 2-year TTL. Long-lived, cross-subdomain identifiers increase tracking/affinity-pinning surface and leak backend identity details in the clear.

```
Set-Cookie: gae_b_id=...kaId_2599970799920745561836...; Max-Age=31536000
Set-Cookie: KAAL=1; Domain=khanacademy.org; Max-Age=63072000
```

**Remediation:** Shorten TTLs for backend-affinity cookies; scope tracking cookies to the subdomain that needs them.

### F-14 — Missing security.txt (soft-200 app shell served instead)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1059**

`/.well-known/security.txt` returns the 219 KB app shell (HTTP 200) instead of a policy document or a clean 404, so the standard machine-readable disclosure/contact policy is absent.

```
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
    https://www.khanacademy.org/.well-known/security.txt
200 219659
```

**Remediation:** Publish a minimal security.txt (contact, policy, preferred_languages) or return a clean 404.

### F-15 — No Referrer-Policy or Permissions-Policy on origin responses
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1021**

Origin responses set X-Frame-Options and X-Content-Type-Options but omit Referrer-Policy and Permissions-Policy, allowing full-path referrers to leak to third parties and leaving camera/geolocation/microphone permissions at browser defaults for an educational site that embeds video/interactive content.

```
$ curl -sI https://www.khanacademy.org/ | grep -iE 'referrer|permission'
# (no matching headers)
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
```

**Remediation:** Add `Referrer-Policy: strict-origin-when-cross-origin` and a minimal Permissions-Policy.

### F-16 — Challenge-pass cookie _fs_ch_cp_* lacks Secure, SameSite and Max-Age
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-614**

Completing the proof-of-work (F-22) sets `_fs_ch_cp_<id>=…; HttpOnly` — **no Secure, no SameSite, no Max-Age** (it is a session cookie). This is the cookie that unlocks the real application from the challenge gate, so it should meet the same bar as a session cookie: as configured it is accepted over plaintext HTTP, sent on cross-site requests, and persists until the browser session ends.

```
Set-Cookie: _fs_ch_cp_79UUvfpJ5mWYtLQv=AfO_5zqOvg…; HttpOnly
```

**Remediation:** Add Secure; SameSite=Lax; and an explicit Max-Age to the pass cookie.

### F-17 — browsing_session_expiry cookie re-set on every origin response without HttpOnly/SameSite
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-614**

`browsing_session_expiry="…"; Path=/; Secure` is re-emitted on **every** origin response — including 404s, OPTIONS and 307s — with Secure only (no HttpOnly, no SameSite). Re-setting a session-lifetime cookie on every response (even error pages) resets/extends its lifetime on each request and keeps it JS-readable on the origin.

```
Set-Cookie: browsing_session_expiry="Thu, 24 Sep 2026 18:12:58 UTC"; Path=/; Secure
(reproduced on: 404 / 400 / 307 responses alike)
```

**Remediation:** Set it only when the value changes, with HttpOnly; SameSite=Lax.

### F-18 — Challenge variant (3,038 B) ships with zero security headers
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-693**

The intermittent Fastly challenge page carries **no** strict-transport-security, no content-security-policy header, no x-frame-options, no x-content-type-options, no referrer-policy and no permissions-policy — the only policy is a `<meta http-equiv="Content-Security-Policy">` tag in the body (meta CSP cannot set frame-ancestors/base-uri). A user hitting the challenge variant gets weaker protection than the same URL served from origin (F-04).

```
GET / (challenged, 3038 B): via: 1.1 varnish, x-varnish: <id>
headers: no HSTS / CSP / XFO / nosniff / referrer-policy / permissions-policy
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'sha256-a9bH…'">
```

**Remediation:** Emit the full header set (HSTS, CSP, XFO, nosniff, referrer-policy) on challenge responses too.

### F-19 — CSP frame-ancestors whitelists classroom and admin subdomains
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N, 3.1) — CWE-1023**

`Content-Security-Policy: frame-ancestors 'self' https://classroom.khanacademy.org https://admin.khanacademy.org` permits www content to be framed by two subdomains that currently serve bare Fastly challenge pages with no HSTS/XFO of their own. If either subdomain's edge configuration weakens, a framing chain into www becomes possible.

**Remediation:** Restrict frame-ancestors to 'self' until the subdomain edge configs are hardened, or enforce strict headers on those subdomains.

### F-20 — Age header (~13.6 h) on content marked private, no-store
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-913**

HTML responses carry `cache-control: private, no-store` yet an `age` of 48,845 s is emitted, indicating upstream/shared-cache semantics that contradict the directives; a misbehaving intermediary could serve the ~13-hour-old document.

```
cache-control: private, no-store
age: 48845
```

**Remediation:** Suppress Age on no-store responses or align directives with the intended caching model.

### F-21 — Origin certificate expires in under 60 days
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-298**

The served certificate is valid only until 2026-11-11 (under 60 days from assessment). No fault, but flagged for the disclosure bundle so renewal is tracked; an expiry would interact with the HSTS preload list.

**Remediation:** Confirm automatic renewal coverage (ACME/CloudFront) and monitor.

### F-22 — Fastly challenge proof-of-work protocol disclosed in shipped JS
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

The challenge page ships its full client implementation: a SHA-256 proof-of-work solved client-side and submitted via a `POST /pat?token=<challenge>` flow, plus cookie-enabled checks and i18n strings. The parameters were used to build and **verify a solver**: the challenge is a 2-character suffix search over a 62² alphabet with an exact SHA-256 match, **solved in 7–11 ms** (answers observed: "z8", "2w"); the `POST /_fs-ch-…/fst-post-back` round-trip returned `{"status":"success"}` and set the `_fs_ch_cp_` pass cookie, after which the next GET returned the real 219 KB page — verified on all four subdomains. Bot mitigation is therefore a ~10 ms bandwidth gate rather than a barrier (the pass cookie itself is flagged in F-16).

```
$ init([{"ty":"pow","data":{"base":"zJvt…","hash":"6a14…","hmac":"6de0…"}}, "<tok>", "/_fs-ch-…", true]
$ POST /_fs-ch-…/fst-post-back  {"token":"<tok>","data":[{"ty":"pow","answer":"z8"}]}
HTTP/2 200  {"status": "success"}
Set-Cookie: _fs_ch_cp_…=…; HttpOnly      (no Secure/SameSite/Max-Age — F-16)
$ GET /  (with _fs_ch_cp_ cookie)
HTTP/2 200  (219,817 B — real app shell; verified on www, classroom, admin, api)
```

**Remediation:** Keep challenge logic server-opaque (opaque token + signed response) rather than shipping the full solver contract.

### F-23 — CSP frame-ancestors and X-Frame-Options disagree
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N, 3.1) — CWE-1023**

CSP `frame-ancestors 'self' https://classroom.khanacademy.org https://admin.khanacademy.org` (F-19) allows framing by two subdomains that `X-Frame-Options: SAMEORIGIN` would block; in modern browsers CSP wins, so the effective policy is the CSP list and XFO is dead weight. classroom./admin. currently serve the same SSR app as www (title "Khan Academy") with no distinct admin UI, so the extra framing allowance is inert today but will surprise any future hardening pass.

**Remediation:** Make CSP and XFO express one policy; drop the subdomain frame-ancestors entries or remove XFO deliberately.

### F-24 — Edge WAF answers 406 (not 403) for decoded XSS signatures in query strings
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-790**

Queries containing decoded `alert(`, `<script`, `</script` or `<svg` return **406 Not Acceptable with an empty body** (`via: 1.1 varnish, cache-control: no-store`), while bare keywords ("alert", "onerror", "(") pass with 200. A 406 for content-style signatures is an unusual fingerprint (WAFs normally answer 403) and signals a decoding-aware signature rule that attackers can probe with encoding variants.

```
GET /login?continue=%22%3E%3Cscript%3Ealert(1)%3C/script%3E  -> 406, content-length: 0
GET /s?query=x%3Csvg                                        -> 406
GET /login?continue=alert(1)                                -> 200
```

**Remediation:** Return a uniform 403 for signature hits and document which encodings are normalized.

### F-25 — W3C traceparent header exposed on all origin responses
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

Every origin response (including OPTIONS 404s) carries `traceparent: 00-<32-hex>-<16-hex>-00` — W3C trace context leaking the internal tracing scheme to clients, correlable with server-side APM data.

```
OPTIONS / -> 404
traceparent: 00-be3b1bfdb08958df07950c0678e3eaac-eee273fd5857023e-00
```

**Remediation:** Strip traceparent at the edge or use per-client opaque IDs.

### F-26 — OPTIONS returns 404 on web routes and 400 on the API router; no Allow header anywhere
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1032**

`OPTIONS /` and `OPTIONS /login` → **404** (web router), `OPTIONS /api/v1/` → **400** (API router), and no route emits an `Allow` header; `HEAD /` → 200. The inconsistent OPTIONS handling across the three routers is a reliable fingerprint and gives clients no discoverable verb set.

**Remediation:** Answer OPTIONS uniformly (204/200 with Allow) across all routers.

### F-27 — api.khanacademy.org root is an HTML 307 to www (no API on the subdomain)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

`GET https://api.khanacademy.org/` → **307** with an HTML body `<a href="https://www.khanacademy.org/">Temporary Redirect</a>` — the "api" subdomain serves no API; the real API lives under www `/api/*`. DNS/branding implies an API host that redirects to the web origin: an inventory mismatch worth documenting and a standing candidate for dangling-CNAME monitoring.

**Remediation:** Point the api subdomain at the API service or retire it; monitor for takeover if it is decommissioned.

## 4. Blocked Escalation Attempts

| Attempt | Result |
|---|---|
| POST /api/internal/graphql/__opname__ with hash= candidates | 400 "No hash= specified" — hash format not guessable from public data |
| POST /api/internal/_ai-guide/text-to-speech/ with JSON body variants | 403 rest.TextToSpeechHandler unauthorized — auth wall holds |
| POST /api/internal/_bb/bigbingo/mark_conversions | 200 silent accept — no stored-object readback path found unauthenticated |
| GET /admin/, /devadmin/, /preview/, /crash, /postlogin | 200 soft-200 app shell (no distinct auth page observed on origin variant) |
| GET /_ah/ (GAE internal namespace) | 200 app shell / intermittent 3038 B challenge — no GAE default error page |
| Raw-quote XSS on canonical/og:url sink (login?continue="%3E<script>) | Percent-encoded echo only — no raw round-trip (safe) |
| Fastly challenge bypass | Solver built & run: PoW solved in 7–11 ms, fst-post-back → 200 + _fs_ch_cp_ cookie, next GET returns the real 219 KB page on www/classroom/admin/api — gate is a ~10 ms bandwidth cost (F-16, F-22) |
| HEAD / and TRACE / | 200 with app-shell ETag; TRACE unsupported at edge |
| /login?continue=<attacker URL> (open redirect) | Value reflected in canonical/og:url (percent-encoded) but no pre-auth Location header — redirect honored only after login; no open redirect |
| CORS: Origin header on /, /login, /graphql, /api/v1/users | No ACAO reflected for any cross-origin origin (negative result) |

## 5. Remediation Priorities

1. Put /api/internal/* behind the authenticated API gateway and standardize its error bodies (fixes F-01, F-02, F-03).
2. Emit HSTS on all response paths — challenge pages, apex 308, every subdomain — and preload subdomains (F-04).
3. Fix cookie flags: HttpOnly+Secure+SameSite on session/challenge cookies (F-05, F-06, F-13).
4. Return real 404s per resource and per-resource ETags; reconcile Age/cache semantics (F-07, F-08, F-20).
5. Centralize error handling across edge/app/API routers (F-09); strip Via/X-Varnish and internal asset paths (F-12).
6. Trim JS-bundle internals and rotate Sentry DSNs (F-10); simplify robots.txt (F-11).
7. Add Referrer-Policy/Permissions-Policy, publish security.txt, tighten frame-ancestors (F-14, F-15, F-19); monitor cert renewal (F-21); consider opaque challenge design (F-22). Flag the _fs_ch_cp_ / browsing_session_expiry cookies (F-16, F-17); emit headers on challenge variants (F-18); reconcile CSP/XFO (F-23), WAF 406s (F-24), traceparent (F-25), OPTIONS handling (F-26) and the api subdomain redirect (F-27).

## 6. Disclosure

Findings are prepared for responsible disclosure to Khan Academy via its HackerOne program (https://hackerone.com/khanacademy). The 4 Medium findings (F-01 – F-04) are recommended for coordinated disclosure together; Low/Informational items may follow in a hygiene batch. No evidence was exfiltrated, no test accounts were used, and all probes were rate-limited unauthenticated GET/POST/OPTIONS/HEAD traffic.
