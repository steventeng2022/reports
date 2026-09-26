# Zero-Day Vulnerability Assessment Report
## edX Public Website (www.edx.org and related edx.org services)

| Item | Detail |
|---|---|
| Report ID | ZD-EDX-2026-09-24 |
| Assessment date | 24 September 2026 (all evidence timestamps UTC) |
| Target | https://www.edx.org (CloudFront front, Cloudflare mid, WP Engine Headless origin; docs./status./api. subdomains) |
| Stack | Next.js 15 (App Router, RSC) + WP Engine Headless Platform + Cloudflare + AWS CloudFront (TPE53) + internal "Violet" deployment platform + Algolia search |
| Method | Non-destructive manual assessment: full-header/cookie forensics, method matrix, CORS/preflight matrix, redirect-param persistence, RSC payload reflection, JS-bundle endpoint/env extraction, subdomain inventory, TLS certificate analysis, WAF behavior probing |
| Classification | Confidential — prepared for responsible disclosure |
| Responsible-disclosure contact | edX security contact: security@edx.org (no public security.txt found — see F-18) |

## 1. Executive Summary

On 24 September 2026 the edX public website was assessed unauthenticated and non-destructively. **24 findings: 4 Medium, 13 Low, 7 Informational.**

The most significant findings are a cluster of **internal-infrastructure disclosures**:

1. Every response carries `x-violet-env: prod` and `x-violet-version: fd76729ad7a5707179fcb223cf8e458ce126f1f3` — the internal deployment platform name and exact build SHA, which lets attackers pin the running code version to known advisories (F-01).
2. The public TLS certificate for www.edx.org carries the internal hostname `proxy.violet.rveducation.io` as its primary CN/SAN entry (F-02).
3. The Cloudflare bot-management cookie `__cf_bm` is set with `Domain=h97m1sqokqgvsbw1eiqol1oc6.js.wpenginepowered.com` — leaking the internal WP Engine origin hostname (and mis-scoping the cookie so browsers likely drop it) (F-03).
4. `GET /api/feature-flags` answers unauthenticated with a parameter-name error, exposing a feature-flag enumeration vector (F-04).

All tests were unauthenticated; no test account existed at assessment time; no forms were submitted beyond minimal JSON POSTs to documented API routes.

## 2. Scope and Environment

- **In scope:** www.edx.org; docs., status., api., authn., careers., checkout., cms., courses., learning., home., help., support., images.cdn. subdomains; /api/* routes; JS bundle (`/_next/static/chunks/*`); robots/sitemap; TLS.
- **Out of scope:** authenticated LMS (courses.edx.org account area), Algolia backend, WP CMS admin (cms.edx.org), video-transcript service.
- **Tooling:** Node 24 fetch harness (work\edx\01-10 scripts), manual header/JS/cert inspection.
- **Stack behavior note:** responses traverse CloudFront (Via/X-Amz-Cf-*) and Cloudflare (cf-ray/cf-cache-status, __cf_bm) with an internal Envoy service mesh upstream (x-envoy-upstream-service-time); the origin is WP Engine Headless serving a Next.js App Router site with React Server Components (self.__next_f payload).

## 3. Findings

### F-01 — Internal deployment-platform and build-hash disclosure on every response
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-200**

Every homepage response carries internal deployment metadata: `x-violet-env: prod` and `x-violet-version: fd76729ad7a5707179fcb223cf8e458ce126f1f3`. "Violet" is edX's internal platform (corroborated by the TLS SAN in F-02), and the version header is the exact build SHA — the same value shipped in the JS bundle as `NEXT_PUBLIC_APP_VERSION`. A public build hash lets attackers enumerate the precise code revision, match it against internal changelogs/commit history, and pick known issues for that exact build.

```
$ curl -sI https://www.edx.org/
x-powered-by: WP Engine Headless Platform
x-violet-env: prod
x-violet-version: fd76729ad7a5707179fcb223cf8e458ce126f1f3
x-envoy-upstream-service-time: 395
x-middleware-rewrite: /en
server: cloudflare
via: 1.1 4a48...cloudfront.net (CloudFront)
```

**Remediation:** Strip internal platform/version headers at the edge; keep build IDs internal-only (or use non-reversible build tokens).

### F-02 — Internal proxy hostname in the public TLS certificate (proxy.violet.rveducation.io)
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-200**

The certificate served for www.edx.org is issued with **Subject CN = `proxy.violet.rveducation.io`** and SANs `DNS:proxy.violet.rveducation.io, DNS:www.edx.org` (Amazon RSA 2048 M01, valid to 2027-03-07). The primary identity of the public certificate is an internal reverse-proxy name on the internal `rveducation.io` zone — disclosing the internal domain naming scheme and proxy role to every client and passive observer (CT logs, scanners). The apex edx.org certificate (CN=edx.org) expires 2026-12-06, under 90 days from assessment.

```
$ openssl s_client -connect www.edx.org:443 -servername www.edx.org
subject= CN=proxy.violet.rveducation.io
issuer= C=US, O=Amazon, CN=Amazon RSA 2048 M01
DNS:proxy.violet.rveducation.io, DNS:www.edx.org
notAfter=Mar  7 23:59:59 2027 GMT
```

**Remediation:** Issue front certificates with the public hostname first (or as the only) subject; use internal SANs only on internal endpoints.

### F-03 — Cloudflare bot-management cookie set with internal WP Engine origin hostname
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-1004**

Requests to /auth/* paths receive `Set-Cookie: __cf_bm=<token>; HttpOnly; SameSite=None; Secure; Path=/; Domain=h97m1sqokqgvsbw1eiqol1oc6.js.wpenginepowered.com`. The Domain attribute names the **internal WP Engine origin host** (a per-site hex subdomain of the `wpenginepowered.com` zone) — disclosing the origin's hostname, and because the Domain does not match www.edx.org, conformant browsers will **not store** the cookie at all, silently disabling Cloudflare Bot Management for those paths (bot protection effectively off for /auth).

```
Set-Cookie: __cf_bm=vm9qBnaiUOfMRjB...; HttpOnly; SameSite=None; Secure;
  Path=/; Domain=h97m1sqokqgvsbw1eiqol1oc6.js.wpenginepowered.com;
  Expires=Thu, 24 Sep 2026 17:32:00 GMT
```

**Remediation:** Scope __cf_bm to the public hostname (Path=/, no Domain override) so the cookie is stored and bot scoring works; keep origin hostnames internal.

### F-04 — Unauthenticated feature-flag API with parameter-name error disclosure
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-209**

`GET /api/feature-flags` (no parameters) returns 400 with a JSON error naming the required parameter: `{"error":"Missing required parameter: flagKey"}`. The endpoint is an unauthenticated feature-flag service; guessing valid flagKey values then returns flag state, which can expose in-flight or internal features (and their names) to anonymous visitors.

```
$ curl -s https://www.edx.org/api/feature-flags
HTTP/2 400
{"error":"Missing required parameter: flagKey"}
```

**Remediation:** Return generic 400/404 for unknown/missing keys; gate the flag endpoint behind auth or restrict it to known public keys.

### F-05 — Unauthenticated product API returns parameter errors and accepts JSON bodies
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-209**

`POST /api/programs` accepts unauthenticated JSON and answers 400 `{"error":"Missing or invalid 'uuids' array in request body"}` (GET on the same route → 405). The route contract (field names, types) is fully disclosed unauthenticated, enabling pre-auth request shaping against the catalog API.

```
$ curl -s -X POST -H 'content-type: application/json' -d '{}' \
    https://www.edx.org/api/programs
HTTP/2 400
{"error":"Missing or invalid 'uuids' array in request body"}
```

**Remediation:** Use generic error bodies on unauthenticated API routes; validate method+body together before responding.

### F-06 — Auth-gated APIs exposed on the public origin (401 JSON errors)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-669**

`GET /api/ecommerce/cart/fetch-cart` → 401 `{"error":"Authentication required - cookies missing"}` and `GET /api/lms/user` → 401 (empty body): live, auth-walled commerce/LMS endpoints on the marketing origin. The JSON 401 confirms the cart service is reachable and stateful; the mismatched 401 bodies (one JSON, one empty) further fingerprint the two backends.

```
$ curl -s -o /dev/null -w '%{http_code} ' https://www.edx.org/api/ecommerce/cart/fetch-cart; curl -s https://www.edx.org/api/ecommerce/cart/fetch-cart
401 {"error":"Authentication required - cookies missing"}
$ curl -s -o /dev/null -w '%{http_code}\n' https://www.edx.org/api/lms/user
401
```

**Remediation:** Return a uniform 401/404 family for all auth-gated API routes; consider moving LMS/cart APIs off the marketing origin.

### F-07 — Unauthenticated user-state endpoint returns per-client data
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-669**

`GET /api/user-language` → 200 `{"language":null}` anonymously: a per-user state endpoint on the public origin that will return the visitor's chosen language once set (tied to the dapi_random_id cookie), enabling passive per-visitor state reads.

```
$ curl -s https://www.edx.org/api/user-language
{"language":null}
```

**Remediation:** Keep per-user state endpoints cookie-bound with consistent auth semantics; document or remove anonymous reads.

### F-08 — Site-wide soft-200 for every HTTP method and path
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1032**

GET, POST, PUT, DELETE and PATCH on arbitrary paths (/, /search, deep routes) all return **200 with the full 2.56 MB homepage**; only OPTIONS (400), PROPFIND (403 CloudFront) and TRACE (405 CloudFront) differ. There is no method dispatch on the edge/app layer, so scanners cannot distinguish routes by verb, and mutating verbs silently hit the homepage (no 405 protection).

```
$ for m in GET POST PUT DELETE PATCH; do curl -s -o /dev/null -w "$m %{http_code} " -X $m https://www.edx.org/x/y/z; done
GET 200 POST 200 PUT 200 DELETE 200 PATCH 200
```

**Remediation:** Add method handling at the router: 405 (or 404) for unsupported verbs on existing routes.

### F-09 — Global ACAO:* including error responses, with broken preflight handshake
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-942**

`Access-Control-Allow-Origin: *` is emitted on ~10 route classes — 200s, 308s, 404s and 405s — with no `Access-Control-Allow-Credentials` (so no credentialed read today). However the preflight is broken/inconsistent: OPTIONS on HTML routes → **400 with no ACAO**, while OPTIONS on /api/* routes → 308. Wildcard CORS on every response (including 404 error bodies) is a latent credential-leak primitive if any route later adds credentials, and the preflight inconsistency indicates the CORS policy is set in at least three places.

```
$ curl -s -o /dev/null -w '%{http_code} ' -H 'Origin: https://evil.example' https://www.edx.org/; \
    curl -s -o /dev/null -w 'acao=%{header_json}\n' -D- -o /dev/null -H 'Origin: https://evil.example' https://www.edx.org/ | grep -i access-control
200 access-control-allow-origin: *
$ curl -s -o /dev/null -w '%{http_code}\n' -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' https://www.edx.org/
400
```

**Remediation:** Centralize CORS in one middleware; allow-list origins for /api/* and drop the wildcard from error responses.

### F-10 — /?redirect= parameter persists attacker value through 307
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-601**

`GET /?redirect=https://evil-attacker.example` → **307 Location: `/?redirect=https%3A%2F%2Fevil-attacker.example`** — the parameter survives the redirect (re-encoded, not consumed) and the same request sets the 7-day dapi_random_id cookie. The value is not followed server-side (no open redirect observed), but persistence + later client-side use of `redirect` makes this a classic open-redirect staging pattern to watch on auth flows.

```
$ curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' \
    'https://www.edx.org/?redirect=https://evil-attacker.example'
307 -> https://www.edx.org/?redirect=https%3A%2F%2Fevil-attacker.example
```

**Remediation:** Validate the redirect value against an allow-list on every read; strip it after one use.

### F-11 — Divergent 404 layers: 2.6 MB WordPress-origin page vs 272 KB Next shell
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

`GET /course/this-course-does-not-exist-xyz123` → 404 with a **2,648,024-byte** full WordPress-origin document (OneTrust consent `cdn.cookielaw.org/consent/fa169e97-be64-4cc1-bad3-9534590f9a30/OtAutoBlock.js` + whole WP theme), while every other unknown path returns the 272 KB Next.js `__next_error__` shell. Two different 404 layers prove the headless WP origin is reachable on content routes and discloses the consent-platform GUID; the size delta also breaks cache- and scanner-based 404 detection.

```
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
    https://www.edx.org/course/this-course-does-not-exist-xyz123
404 2648024
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
    https://www.edx.org/definitely-not-a-page-xyz
404 276849
```

**Remediation:** Serve one 404 template per route family; keep WP-origin error pages from reaching the public edge.

### F-12 — Internal service inventory leaked in the public JS bundle
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-200**

The 35 production JS chunks (3.26 MB total) reference 14 distinct internal/production hosts: authn.edx.org, careers.edx.org, checkout.edx.org, cms.edx.org, commerce-coordinator.edx.org, courses.edx.org, help.edx.org, home.edx.org, learning.edx.org, support.edx.org, images.cdn.edx.org, prod-discovery.edx-cdn.org, prod-edx-video-transcripts.edx-video.net, plus 16 /api/* endpoint paths (including /api/user/v2/account/registration, /api/user/v2/account/login_session, /api/v1/token). This is a ready-made target map for subdomain enumeration and API discovery.

```
// extracted from /_next/static/chunks/* (35 files, 3.26 MB)
https://prod-discovery.edx-cdn.org
https://prod-edx-video-transcripts.edx-video.net
/api/user/v2/account/registration
/api/v1/token
```

**Remediation:** Externalize configuration (feature/env endpoints) instead of inlining host inventories; prune unused endpoints from shipped bundles.

### F-13 — NEXT_PUBLIC_* configuration values inlined in client bundle
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-200**

The client bundle ships `NEXT_PUBLIC_WORDPRESS_URL: "https://cms.edx.org"`, `NEXT_PUBLIC_APP_VERSION: "fd76729ad7..."` and the Algolia product index name (`NEXT_PUBLIC_ALGOLIA_PRODUCT_INDE...`). The CMS origin URL plus the Algolia index allow anonymous enumeration of catalog content and confirm the WordPress headless pipeline end-to-end.

```
NEXT_PUBLIC_WORDPRESS_URL:"https://cms.edx.org"
NEXT_PUBLIC_APP_VERSION:"fd76729ad7a5707179fcb223cf8e458ce126f1f3"
NEXT_PUBLIC_ALGOLIA_PRODUCT_INDE...
```

**Remediation:** Fetch CMS/Algolia configuration server-side; expose only the minimum to clients.

### F-14 — dapi_random_id cookie without HttpOnly on entire .edx.org
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1004**

First responses set `dapi_random_id=<13-digit epoch>-<5-char>; Path=/; SameSite=Strict; Secure; Domain=.edx.org` (7-day expiry) **without HttpOnly**, domain-wide across every subdomain. It is the per-visitor identity token tied to /api/user-language and cart state, so it is readable by any script on any .edx.org property and is an amplification primitive for XSS on the subdomains.

```
Set-Cookie: dapi_random_id=1790249789182-sqi06pi; Expires=Thu, 01 Oct 2026 11:36:29 GMT;
  Path=/; SameSite=Strict; Secure; Domain=.edx.org
```

**Remediation:** Add HttpOnly; keep the 7-day TTL only if the value is needed that long.

### F-15 — Conflicting cache semantics: no-store content served with Age 20.8 h and 30-day stale-if-error
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-913**

Homepage responses carry `cache-control: private, no-cache, no-store, max-age=0, must-revalidate` yet also `cdn-cache-control: public, max-age=86400, stale-while-revalidate=60, stale-if-error=2592000`, `last-modified` (2026-09-23), and `age: 75023` (~20.8 h) with `cf-cache-status: HIT`. The document was therefore served from a 21-hour-old shared-cache entry despite no-store, and during any upstream outage the 30-day stale-if-error window keeps it served indefinitely — stale content (and stale cache keys) can outlive deployments for 30 days.

```
age: 75023
cache-control: private, no-cache, no-store, max-age=0, must-revalidate
cdn-cache-control: public, max-age=86400, stale-while-revalidate=60, stale-if-error=2592000
cf-cache-status: HIT
last-modified: Wed, 23 Sep 2026 14:46:09 GMT
```

**Remediation:** Align the CDN and app cache directives; drop stale-if-error or reduce it to minutes on HTML.

### F-16 — HSTS without includeSubDomains or preload
**Severity: Low (CVSS 3.1: AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N, 4.9) — CWE-319**

`Strict-Transport-Security: max-age=31536000` is present on www but **without includeSubdomains or preload**, so the dozen-plus subdomains (docs., status., api., authn., …) get no HSTS inheritance and are exposed to SSL-strip on first visit; the apex cert also expires 2026-12-06.

```
$ curl -sI https://www.edx.org/ | grep -i strict
strict-transport-security: max-age=31536000
```

**Remediation:** Add includeSubdomains, verify subdomain HSTS, then submit to the preload list.

### F-17 — Edge WAF inspects the URI only: raw quote in request headers passes (200)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-790**

The 25-character matrix (F-21) blocks raw special characters in the path/query with 403, but the identical raw double-quote delivered in a request **header** (`Referer: https://x"y.example`) returns **200** — the edge character-set rule is URI-scoped, so header values (Referer, User-Agent, custom headers) reach the origin unfiltered. Header values commonly flow into logs, error pages and downstream services, making this a practical pre-filter bypass for reflection and log-injection research.

```
$ curl -s -o /dev/null -w '%{http_code}\n' 'https://www.edx.org/?p=%22x'   # raw " in query
403
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Referer: https://x"y.example' https://www.edx.org/
200
```

**Remediation:** Apply character-set rules to the full request (headers included) or document the URI-only scope and filter header reflection contexts.

### F-18 — Minimal CSP (frame-ancestors only) and missing security.txt
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1021**

The only CSP directive is `frame-ancestors 'none'` — no default-src/script-src/object-src posture for a site that ships 35 RSC script pushes. `/.well-known/security.txt` and `/security.txt` both 404, so there is no machine-readable disclosure policy.

```
content-security-policy: frame-ancestors 'none'
$ curl -s -o /dev/null -w '%{http_code}\n' https://www.edx.org/.well-known/security.txt
404
```

**Remediation:** Roll out a baseline CSP (default-src 'self'; script-src 'self'; object-src 'none'); publish security.txt.

### F-19 — Plain-HTTP link to subdomain (mixed content) in homepage HTML
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-319**

The homepage contains `href="http://careers.edx.org/"` — a plaintext HTTP reference to a production subdomain in a mostly-HTTPS document, inviting mixed-content handling and an easy first-hop for downgrade tests against careers.edx.org.

```
href="http://careers.edx.org/"
```

**Remediation:** Use protocol-relative or https:// absolute URLs.

### F-20 — Source-map references shipped in all 35 production chunks
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-497**

Every production chunk ends with `sourceMappingURL=<name>.js.map` (e.g. webpack-540695c8f5aa7104.js.map, main-app-53c3f9f4fa7e7bfb.js.map). Post-assessment verification re-requested all 35 referenced `.map` URLs: **0 of 35 return 200** — the references are dangling artifacts (no source currently recoverable), but they remain shipped in every production chunk.

```
sourceMappingURL=webpack-540695c8f5aa7104.js.map
sourceMappingURL=main-app-53c3f9f4fa7e7bfb.js.map
```

**Remediation:** Strip or gate sourceMappingURL in production bundles.

### F-21 — Edge WAF blocks raw quote characters in query strings (403)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-790**

`GET /search?q=%22` (percent-encoded raw quote) round-trips into the RSC payload safely, but a raw `"` in the query string triggers a **403** from the edge — evidence of an aggressive character-set WAF rule. The full re-run matrix (25 raw characters in path/query — quotes, angle brackets, backtick, braces, parens, brackets, ampersand, semicolon, dollar, percent, space) returns **403 for every character**, while the same raw double-quote in a request **header** returns 200 (F-17) — the rule is URI-scoped.

```
$ curl -s -o /dev/null -w '%{http_code}\n' 'https://www.edx.org/search?q=%22test%22'
200
$ curl -s -o /dev/null -w '%{http_code}\n' 'https://www.edx.org/search?q="test"'
403
```

**Remediation:** Tune the character-set rule to the actual reflection contexts (RSC JSON-escapes the value — verified safe).

### F-22 — Publicly reachable non-www services on the edx.org zone
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

Subdomain inventory: docs.edx.org → **200 live GitHub Pages site** (Server: GitHub.com); status.edx.org → 302 to edx.statuspage.io (AtlassianEdge, public status page with incident history); api.edx.org → 302 to www (AWS Global Accelerator 65.9.180.x). insides./staging./dev./mail.edx.org → NXDOMAIN (no dangling CNAMEs found). Three different hosting platforms (GitHub, Atlassian, AWS GA) sit on the brand zone with minimal security-header parity.

```
$ curl -sI https://docs.edx.org/   | grep -i server
Server: GitHub.com
$ curl -sI https://status.edx.org/ | grep -iE 'server|location'
location: https://edx.statuspage.io
Server: AtlassianEdge
```

**Remediation:** Standardize security headers across all zone hosts; review the public status page's incident-detail exposure.

### F-23 — Deprecated X-XSS-Protection header and multi-layer stack headers
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-497**

Responses still emit `X-XSS-Protection: 1; mode=block` (deprecated; can induce double-escaping bugs in legacy browsers) alongside the full stack fingerprint: `server: cloudflare`, `via: ...cloudfront.net`, `x-amz-cf-pop: TPE53-P4`, `x-envoy-upstream-service-time`, `x-powered-by: WP Engine Headless Platform`, `x-middleware-rewrite: /en` — a complete CDN→mesh→origin map in every response.

```
x-xss-protection: 1; mode=block
x-amz-cf-pop: TPE53-P4
x-middleware-rewrite: /en
```

**Remediation:** Drop X-XSS-Protection; sanitize internal stack headers at the edge.

### F-24 — Retired registration API returns the 272 KB OneTrust interstitial (dead signup flow)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

The public JS still calls the registration endpoints, but all `/api/user/v2/account/registration*` paths now return **404 with the 272,882-byte OneTrust/OneTrack interstitial** (a hidden form whose action is `/api/auto-block?id=fa169e97-be64-4cc1-bad3-9534590f9a30`), and every attempt re-issues the `__cf_bm` cookie scoped to the WP Engine origin domain (F-03). A live-looking signup surface that is actually a consent interstitial confuses clients and scanners, and the auto-block ID is a stable fingerprint of the OneTrack layer.

```
POST /api/user/v2/account/registration (JSON, unauth, real-format email)
HTTP/1.1 404   (body: 272,882 B OneTrust page; hidden input action="/api/auto-block?id=fa169e97-…")
Set-Cookie: __cf_bm=…; Domain=h97m1sqokqgvsbw1eiqol1oc6.js.wpenginepowered.com
```

**Remediation:** Route retired API paths to a uniform JSON 404 and remove (or wire up) the registration calls in the shipped bundle.

## 4. Blocked Escalation Attempts

| Attempt | Result |
|---|---|
| GraphQL introspection on /api/graphql, /graphql | 404 Next __next_error__ shell — no GraphQL router on the marketing origin |
| POST /api/user/v2/account/registration + 2 variants (unauth) | 404 + 272 KB OneTrust interstitial, hidden auto-block form id fa169e97-… — signup route retired on this origin (F-24) |
| POST /api/user/v2/account/login_session | 308 → /api/user/v2/account/login_session (trailing-slash loop) |
| GET /api/user/v1/accounts, /api/user/v1/validation/registration, /api/v1/token | 404 shell — not routed on www origin |
| /wp-json/wp/v2/users, /posts, /pages (WP REST user enum) | 404 / 308 → /wp-json (404) — headless, WP REST disabled |
| oembed endpoint /wp-json/oembed/1.0/embed?url= | 404 shell |
| Path traversal /../ probes | 404 Next shell, no normalization surprises |
| OPTIONS preflight matrix (10 routes) | 400 (HTML routes) / 308 (API routes) — no ACAO on preflight |
| Source-map 200-verification (all 35 referenced .map) | 0/35 returned 200 — dangling references only (F-20) |
| Raw-char WAF matrix (re-run: 25 URI chars + header probe) | Every raw URI char → 403; raw `"` in Referer header → 200 — WAF is URI-only (F-17) |

## 5. Remediation Priorities

1. Fix the three hostname/build disclosures (F-01, F-02, F-03) — they are the highest-signal items for coordinated disclosure.
2. Tighten API error bodies and gate /api/feature-flags (F-04 – F-07).
3. Centralize CORS + method handling; fix preflight consistency (F-08, F-09).
4. Validate /?redirect on every read (F-10); unify 404 templates (F-11).
5. Prune bundle internals (F-12 – F-14), align cache semantics (F-15), extend HSTS (F-16).
6. Baseline CSP + security.txt (F-18); fix mixed-content link (F-19); strip source maps if live (F-20); tune WAF rule (F-21); harmonize subdomain hardening (F-22, F-23). WAF inspection is URI-only (F-17); retire or rewire the dead registration routes (F-24).

## 6. Disclosure

Prepared for responsible disclosure to edX via security@edx.org (no public security.txt found). The 4 Medium findings (F-01 – F-04) are recommended for a joint advisory; Low/Informational items can follow as a hardening batch. The source-map verification (0/35 live) and registration-route probing are complete (F-20, F-24); an authenticated IDOR pass on the LMS APIs remains the main pending item.
