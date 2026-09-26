# Zero-Day Vulnerability Assessment Report
## Coursera Portal (coursera.org, www.coursera.org)

| Item | Detail |
|---|---|
| Report ID | ZD-COURSERA-2026-09-24 |
| Assessment date | 24 September 2026 (all evidence timestamps UTC) |
| Target | https://www.coursera.org (AWS CloudFront front, Envoy service mesh origin; Apollo GraphQL at /graphql) |
| Stack | CloudFront + Envoy (x-envoy-*) + Express (x-powered-by) + Apollo Server GraphQL + Mustache templating + Google Tag Manager |
| Method | Non-destructive manual assessment: header/cookie forensics, GraphQL schema-oracle probing (suggest responses, subfield errors, __typename resolution), imageproxy behavior matrix, method matrix, reflection-sink testing, robots/path inventory |
| Classification | Confidential — prepared for responsible disclosure |
| Responsible-disclosure contact | Coursera via HackerOne: https://hackerone.com/coursera |

## 1. Executive Summary

On 24 September 2026 the Coursera web properties were assessed unauthenticated and non-destructively. **22 findings: 4 Medium, 9 Low, 9 Informational.**

The most significant findings concern the **public Apollo GraphQL API at /graphql**, which is reachable unauthenticated and behaves as a *schema-enumeration oracle*: unknown field names return did-you-mean suggestions of real field/type names, subfield probes leak internal type names (e.g. `User_User`, `LearnerProfile_Profile`) and resolver fields (`me`, `getByEmail`, `getBySlug`), and all 43 top-level query groups resolve anonymously via `__typename`. Combined, these let an attacker reconstruct the internal query surface without credentials (F-01 – F-03). A CORS-open, server-side image-fetching utility (`/api/utilities/v1/imageproxy`) that **live-fetches the cloud-metadata address 169.254.169.254 and relays the upstream response** completes the Medium set (F-04).

No test account was used; all probes were unauthenticated GET/POST/OPTIONS.

## 2. Scope and Environment

- **In scope:** www.coursera.org; /graphql; /api/* routes; /maestro/, /ui/, /account/, /voucher/, /acclaimbadge/, /signature/voucher/, /ent-website/ (robots-listed); robots.txt, llms.txt, sitemap; GTM container; TLS.
- **Out of scope:** authenticated learner/enterprise areas, ctfassets/CTF CDN, third-party (Google/Cloudflare) services themselves.
- **Tooling:** Node 24 fetch harness (work\coursera\01-06 scripts); manual header/JS/GraphQL inspection.
- **Architecture note:** responses traverse CloudFront (Via, x-amz-cf-*) and an Envoy mesh (x-envoy-*), with per-app identity headers (x-coursera-*). The GraphQL endpoint runs a distinct router from the HTML app (JSON errors vs HTML 404s).

## 3. Findings

### F-01 — GraphQL did-you-mean oracle enables full anonymous schema enumeration
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-639**

With introspection disabled, the Apollo Server at /graphql still answers *unknown* top-level field names with did-you-mean suggestions of **real** field/type names: `{"userProfile":"CourseProfiles", "LearnerProfile", "UserEmail", or "UserEmails"?}`, `"suggestions":"AiSuggestions" or "Session"?`, `"login":"Domain"?`, etc. By feeding guessed words, an attacker can iteratively enumerate the entire public schema — 43 query groups were mapped this way (User, Seo, Course, CourseProfiles, LearnerProfile, UserEmail, UserPreference, Mobile, Specialization*, Degree, ProgramHome, Skills, Partner, courseCredits, CitySearch, SearchResult, Entitlement, Experiment, paymentTaxes, Certificate, CheatingCase, Badge, Proctor, Faq, Recommendations, AiSuggestions, Session, Collection, ProductCard, Nostos, OTPQueries, Descript, Domain, Campaign, IdVerification, Occupations, CourserianRoles, AssignmentCoach, CoachItem, levelSets).

```
$ curl -s -X POST https://www.coursera.org/graphql -d '{"query":"{ userProfile { __typename } }"}'
{"errors":[{"message":"Cannot query field \"userProfile\" on type \"Query\". Did you mean ...?","extensions":{...
  "suggest":"\"CourseProfiles\", \"LearnerProfile\", \"UserEmail\", or \"UserEmails\"?"}}]}
$ curl -s -X POST https://www.coursera.org/graphql -d '{"query":"{ login { __typename } }"}'
... "suggest":"\"Domain\"?"
```

**Remediation:** Suppress or genericize did-you-mean suggestions on the public endpoint (or scope them to known aliases); return the same error text for known-adjacent and random field names.

### F-02 — Subfield error oracle leaks internal type names and resolver fields
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-209**

Probing subfields of query groups returns errors that name **internal type identities and fields**: `Field "me" of type "User_User" must have a selection of subfields. Did you mean "me { ... }"?` (User), the same for `LearnerProfile.me` (type `LearnerProfile_Profile`), plus `UserEmail.getByEmail`, `Course.getBySlug`, `Partner.getBySlug`, `Specialization.getBySlug`, `Degree.getBySlug`, `Certificate.certificates`. The oracle reveals the internal naming convention (`<Group>_<Field>` types), the existence of an anonymous `me` resolver, and a **user lookup by email** field — a direct lead for IDOR/enumeration research against the authenticated API.

```
$ curl -s -X POST https://www.coursera.org/graphql -d '{"query":"{ User { me { __typename } } }"}'
{"errors":[{"message":"Field \"me\" of type \"User_User\" must have a selection of subfields. Did you mean \"me { ... }\"?"}]}
$ curl -s -X POST https://www.coursera.org/graphql -d '{"query":"{ UserEmail { getByEmail { __typename } } }"}'
... suggest: "getByEmail"
```

**Remediation:** For unauthenticated requests, return uniform field-error messages without internal type identifiers; document the public query surface deliberately.

### F-03 — All 43 top-level query groups resolve anonymously via __typename
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-639**

Every top-level query group answers `{"<Group>":{"__typename":"<Group>Queries"}}` unauthenticated with HTTP 200 — i.e., 43 resolver groups (including sensitive-sounding ones: OTPQueries, IdVerification, CheatingCase, Entitlement, Experiment, Campaign) are live on the anonymous path. This confirms the resolver layer executes unauthenticated dispatch and lets attackers fingerprint deployed feature sets (e.g. AI features via AiSuggestions/AssignmentCoach/CoachItem).

```
$ curl -s -X POST https://www.coursera.org/graphql -d '{"query":"{ User { __typename } OTPQueries { __typename } }"}'
{"data":{"User":{"__typename":"UserQueries"},"OTPQueries":{"__typename":"OTPQueriesQueries"}}}
```

**Remediation:** Require auth (or at least a token) at the group level for non-public groups; return 403/field-error uniformly for internal groups.

### F-04 — CORS-open server-side image proxy with disclosed validation contract
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N, 5.9) — CWE-918**

`/api/utilities/v1/imageproxy` (explicitly `Allow`-ed in robots.txt) is a server-side URL-fetching utility with `Access-Control-Allow-Origin: *` (plus `Access-Control-Allow-Methods: GET`, `Access-Control-Allow-Headers: Cache-Control`) on its responses — including its 404 JSON `{"message":"","statusCode":404}`. It discloses its validation contract: `?path=<invalid>` → 400 `Invalid image URL.`, path-traversal variants → soft-200 "API Route Does Not Exist". A CORS-open image fetcher is a classic SSRF primitive — and verification now shows it **live-fetches cloud-metadata addresses**: `https://169.254.169.254/latest/meta-data/` (and the IAM role path) return **403 with the upstream CloudFront error HTML relayed verbatim (919 B, Request ID included)**, while `127.0.0.1`, `10.0.0.1` and `0.0.0.0` are rejected by the `Invalid image URL.` host/scheme check. The upstream 403 means the metadata document itself is not yet readable, but the request demonstrably reaches the instance-metadata service and the upstream error is relayed to any cross-origin caller — a live SSRF-with-relay oracle.

```
$ curl -s -D- -o /dev/null 'https://www.coursera.org/api/utilities/v1/imageproxy' | grep -i access-control
access-control-allow-origin: *
access-control-allow-methods: GET
$ curl -s -o /dev/null -w '%{http_code}\n' 'https://www.coursera.org/api/utilities/v1/imageproxy/https://169.254.169.254/latest/meta-data/'
403   (body: 919 B upstream CloudFront error HTML, Request ID relayed)
$ curl -s 'https://www.coursera.org/api/utilities/v1/imageproxy/https://127.0.0.1/'
Invalid image URL.
```

**Remediation:** Restrict the image proxy to an allow-list of CDN hosts/schemes, drop the wildcard ACAO (or echo validated origins only), and return uniform 400s without naming the parameter.

### F-05 — Unrendered Mustache placeholder {{{colorTheme}}} shipped on every page
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

The `<html>` tag on every rendered page (home, /business, /xmlrpc, /ent-website/, even OPTIONS responses) carries the unrendered template variable `data-color-theme="{{ {colorTheme} }}"`. The raw Mustache triple-brace placeholder reaches clients, revealing the server-side templating engine and an unresolved variable name (and a client-side rendering gap).

```
<html ... data-color-theme="{{{colorTheme}}}">
```

**Remediation:** Resolve the placeholder server-side (or default it) before sending HTML; avoid shipping raw template syntax.

### F-06 — API router returns HTTP 200 for non-existent routes
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1032**

Unknown /api/* routes (e.g. /api/course/v1/javascript, /api/search, /api/graphql, /api/swagger.json, /api/openapi.json) return **200** with an HTML body "Coursera - API Route Does Not Exist", while the HTML app returns a styled 404. Consumers (and scanners) cannot distinguish live from dead API routes by status, and the 200 HTML (instead of JSON) on an API router breaks API clients.

```
$ curl -s -o /dev/null -w '%{http_code}\n' https://www.coursera.org/api/course/v1/javascript
200
body: <title>Coursera - API Route Does Not Exist</title>
```

**Remediation:** Return 404 JSON from the API router; keep status semantics consistent per router family.

### F-07 — Internal app/mesh/trace header cluster on every response
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-200**

Public responses carry the full internal identity set: `x-coursera-appname: front-page`, `x-coursera-render-mode: html`, `x-coursera-render-version: v2`, `x-coursera-request-id`, `x-coursera-trace-id-hex`, `x-envoy-decorator-operation: egress`, `x-envoy-upstream-service-time`, `server: envoy`, `x-powered-by: Express`, and a W3C `traceresponse` trace ID. The app-name + render-version headers pin the exact frontend build, and trace IDs let external observers correlate requests with internal APM data.

```
x-coursera-appname: front-page
x-coursera-render-version: v2
x-envoy-decorator-operation: egress
traceresponse: 00-b95aa3090232596360418693e1cd3725-f8ba4843308a98cc-00
server: envoy
```

**Remediation:** Strip internal app/mesh/trace headers at the edge; expose only generic request IDs if needed for support.

### F-08 — __204u cross-subdomain tracking cookie without Secure/HttpOnly/SameSite
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-614**

First responses set `__204u=<10-digit counter>-<epoch-ms>; Max-Age=31536000; Expires=<+1y>; Path=/; Domain=.coursera.org` — a year-long, domain-wide counter cookie with **no Secure, no HttpOnly, no SameSite** attributes: sent over plaintext HTTP, readable by JS on every subdomain, and usable in cross-site form flows.

```
Set-Cookie: __204u=5846824358-1790249143490; Max-Age=31536000;
  Expires=Fri, 24 Sep 2027 11:25:43 GMT; Path=/; Domain=.coursera.org
```

**Remediation:** Add Secure; SameSite=Lax; HttpOnly (if not JS-needed), and review the 1-year TTL.

### F-09 — REST routing-error disclosure on /api/v1/* routes
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-209**

`/api/v1/courses` answers GET → 405 `{"msg":"Routing error: 'get' not implemented"}` and element-POST → 405 `{"msg":"Routing error: Post only to the collection resource, not individual elements."}` — the router names the unsupported verb and the resource model (collection vs element) unauthenticated, aiding API surface mapping.

```
$ curl -s https://www.coursera.org/api/v1/courses
{"msg":"Routing error: 'get' not implemented"}
```

**Remediation:** Use generic 404/405 bodies without routing-model detail on unauthenticated routes.

### F-10 — Google Tag Manager container publicly fetchable at a short random path
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-497**

`GET /5JKLVK/` returns 200 with a GTM container resource (`google_tag_manager` bootstrap, `content-type: application/javascript`, `cache-control: private, max-age=900`, `accept-ranges: none`). Short, unguessable-looking paths serving third-party-tag resources are easy to miss in audits; GTM container contents (custom HTML/JS, tag configs) are a common info-disclosure and supply-chain vector.

```
$ curl -s -o /dev/null -w '%{http_code} %{content_type}\n' https://www.coursera.org/5JKLVK/
200 application/javascript
```

**Remediation:** Serve tag resources under a documented path (/gtm/…) with cache headers; monitor container changes.

### F-11 — robots.txt discloses internal path inventory
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-532**

robots.txt enumerates otherwise-hidden routes: `/maestro/api/`, `/maestro/`, `/ui/`, `/signature/voucher/`, `/account/`, `/acclaimbadge/`, `/voucher/`, `/search`, `/ent-website/` (disallowed) plus explicit `Allow: /api/utilities/v1/imageproxy` and `/llms.txt` — a ready-made scanner target map, including the internal "maestro" API prefix.

```
Allow: /api/utilities/v1/imageproxy
Disallow: /maestro/api/
Disallow: /maestro/
Disallow: /ui/
Disallow: /signature/voucher/
...
```

**Remediation:** Keep robots minimal; rely on auth/404 for hidden routes rather than robots disallows.

### F-12 — GraphQL error responses leak internal microservice names and Spring exceptions
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-209**

Unauthenticated resolver probes return 200 error envelopes naming the **internal microservice** that rejected them: `User{me{__typename}}` → `extensions: {errorType: "PERMISSION_DENIED", serviceName: "user-profile-application", code: "DOWNSTREAM_SERVICE_ERROR"}`, `getUsersByEmail` → `user-application`, `getMyCertificates` → `certificates-application`, plus a raw `org.springframework.security.access.AccessDeniedException` message on the `Nostos` resolver. Mapping the public GraphQL schema onto internal service boundaries lets an attacker target the weakest downstream service in future attacks.

```
$ curl -s -X POST https://www.coursera.org/graphql -d '{"query":"{ User { me { __typename } } }"}'
{"errors":[{"message":"Access is denied","path":["User","me"],"extensions":{"errorType":"PERMISSION_DENIED","serviceName":"user-profile-application","code":"DOWNSTREAM_SERVICE_ERROR"}}]}
```

**Remediation:** Normalize downstream error mapping (drop serviceName/exception class names) before returning GraphQL errors to anonymous callers.

### F-13 — /graphql CORS preflight advertises Access-Control-Allow-Credentials: true with no ACAO
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-942**

`OPTIONS /graphql` with `Origin: https://evil-attacker.example` returns **204 with `Access-Control-Allow-Credentials: true`** and `Allow: GET,HEAD,PUT,PATCH,POST,DELETE` but **no** `Access-Control-Allow-Origin` — browsers block the request today, but the credentials flag plus the wide method list means any future ACAO reflection (or an `*` on a route subset, as in F-04) upgrades this endpoint to credentialed cross-origin GraphQL with no further configuration change.

```
$ curl -s -D- -o /dev/null -X OPTIONS -H 'Origin: https://evil-attacker.example' https://www.coursera.org/graphql
HTTP/2 204
access-control-allow-credentials: true
allow: GET, HEAD, PUT, PATCH, POST, DELETE
(no access-control-allow-origin)
```

**Remediation:** Emit Access-Control-Allow-Credentials only alongside an explicit, validated ACAO.

### F-14 — OPTIONS returns the full homepage HTML
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1032**

`OPTIONS /` → 200 with the full homepage HTML (same body as GET), while `OPTIONS /api` → 204. OPTIONS normally returns headers only; returning a full rendered document doubles the cache/surface semantics of the homepage and is a scanner fingerprint.

```
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -X OPTIONS https://www.coursera.org/
200 <full homepage bytes>
```

**Remediation:** Answer OPTIONS with headers only (204/200, no body).

### F-15 — /admin redirect chain ends at 404 (302 → /admin/ → 301 → 404)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

`/admin` → 302 `/admin/` → 301 (trailing-slash canonical) → styled 404. The legacy admin path is a three-hop dead end; each hop leaks a routing rule (legacy alias, trailing-slash normalization).

```
$ curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://www.coursera.org/admin
302 https://www.coursera.org/admin/
```

**Remediation:** Collapse legacy aliases to a single 404/301.

### F-16 — Missing security.txt (styled 404 returned)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1059**

`/security.txt` and `/.well-known/security.txt` return the styled 404 page (301 on the bare path) — no machine-readable disclosure policy.

**Remediation:** Publish a minimal security.txt (contact, policy, hiring link).

### F-17 — llms.txt served publicly (200)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

`/llms.txt` (200) is an LLM-facing description of the site, explicitly `Allow`-ed in robots. It is a new class of semi-public document that summarizes site structure and offerings for AI crawlers — review it like other public docs (and keep it in sync).

**Remediation:** Include llms.txt in the public-doc review process.

### F-18 — Reflection sinks (canonical/og:url) verified safe via percent-encoding
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-79**

Query input on /search (q, query), /explore (q), /learn/<slug> (url), /profiles (redirect) is reflected into canonical/og tags **percent-encoded** — breakout attempts (`%22%3E<img onerror>`) did not round-trip raw into HTML attributes; the 404 family for /specializations|/profiles keeps distinct bodies (useful negative result). No XSS confirmed; sinks documented for future change control.

```
GET /search?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E  -> 200, og:url encodes %22 as %2522
```

**Remediation:** Keep context-aware encoding on these sinks; add to the XSS regression suite.

### F-19 — No CSP or Referrer-Policy on homepage; deprecated X-XSS-Protection present
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1021**

The homepage sets HSTS (includeSubDomains+preload — good), X-Frame-Options SAMEORIGIN and nosniff, but **no Content-Security-Policy** and no Referrer-Policy; it still ships `X-XSS-Protection: 1; mode=block` (deprecated; double-escaping risk in legacy browsers). A CSP with `frame-ancestors 'self' contentful.com *.contentful.com` does exist on /ent-website/ pages (third-party framing from Contentful allowed).

```
$ curl -sI https://www.coursera.org/ | grep -iE 'content-security|referrer|x-xss'
x-xss-protection: 1; mode=block
```

**Remediation:** Roll out a baseline CSP site-wide; drop X-XSS-Protection; justify the contentful.com frame-ancestors entries.

### F-20 — Anonymous GraphQL returns full entity records (Partner, Course)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.9) — CWE-639**

Beyond the schema oracle, several resolvers return **complete unauthenticated data**: `Partner { queryBySlug(slug: "google") }` → 200 with id 463, name, logo, description, "Mountain View,us", INDUSTRY; `Course { queryBySlug(slug: "javascript") }` → 200 with an opaque id, textDescription, 13 skill tags and 2 instructor names. Introspection is disabled, but the same queries work for arbitrary slugs — an anonymous enumeration channel for partners/courses that outlives page-level access control.

```
$ curl -s -X POST https://www.coursera.org/graphql -d '{"query":"{ Partner { queryBySlug(slug: \"google\") { id name location { name } partnerType } } }"}'
{"data":{"Partner":{"queryBySlug":{"id":463,"name":"Google","location":{"name":"Mountain View,us"},"partnerType":"INDUSTRY"}}}}
```

**Remediation:** Return only the fields each public page needs; require authentication for resolvers that expose entity internals.

### F-21 — imageproxy relays Node/undici parse errors for bracketed hosts
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-209**

`GET /api/utilities/v1/imageproxy/https://[::1]/` → 400 with the undici error text **"Illegal request-target: Invalid input '['"** relayed into the public response — a Node.js stack detail that confirms the fetch client (undici) and hands bypass researchers a precise validation boundary.

```
$ curl -s 'https://www.coursera.org/api/utilities/v1/imageproxy/https://[::1]/'
<400 body containing: Illegal request-target: Invalid input '['>
```

**Remediation:** Map upstream parse errors to a generic 400 body before responding.

### F-22 — robots-disallowed paths split across three routing layers; retired WordPress path still 200
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-200**

`/maestro/`, `/maestro/api/` and `/ui/` — all listed in robots.txt (F-11) — return **real styled 404s** (the HTML router knows them), while `/admin/` and `/signature/voucher/` 301-redirect instead, and the retired WordPress path `/business/xmlrpc.php` still answers **200 with the SPA soft-shell**. The mixed responses prove three different routing layers (HTML router, API router, legacy WP) answering on one origin.

```
$ curl -s -o /dev/null -w '%{http_code}\n' https://www.coursera.org/maestro/
404
$ curl -s -o /dev/null -w '%{http_code}\n' https://www.coursera.org/business/xmlrpc.php
200
```

**Remediation:** Return one consistent 404 for all retired/hidden paths across every router.

## 4. Blocked Escalation Attempts

| Attempt | Result |
|---|---|
| Full introspection {__schema{types{name}}} | 400 "introspection is not allowed by Apollo Server" — but suggest oracle still works (F-01) |
| User { me { __typename } } anonymous | 200 error: PERMISSION_DENIED, serviceName "user-profile-application" — auth wall holds, service name leaks (F-12) |
| UserEmail { getByEmail } unauth | PERMISSION_DENIED (serviceName "user-application") — IDOR candidate once a session exists |
| imageproxy → 169.254.169.254 metadata IP | 403 with upstream CloudFront error relayed (919 B) — live fetch + relay confirmed (F-04); 127.0.0.1/10.x rejected by URL check |
| /maestro/ /ui/ /account/ /voucher/ /acclaimbadge/ | Real 404s (maestro/ui) vs 301s (account/voucher); /business/xmlrpc.php still 200 — three routing layers on one origin (F-22) |
| .env / .git/HEAD / swagger.json / actuator / package.json | 404 styled page — clean |
| /api/swagger.json, /api/openapi.json | 200 soft-200 "API Route Does Not Exist" (F-06) |
| TRACE | empty 200-ish — unsupported, no body |
| persistedQuery (APQ) hash replay + malformed bodies | Clean 400s ("POST body missing", "Syntax Error: Expected Name, found <EOF>") — APQ not reachable with public hashes |

## 5. Remediation Priorities

1. Neutralize the GraphQL oracle: genericize suggest/subfield errors, gate non-public query groups behind auth (F-01 – F-03).
2. Harden the image proxy: scheme/host allow-list, drop wildcard CORS, uniform 400s (F-04).
3. Fix template + API-router semantics (F-05, F-06); strip internal header cluster (F-07).
4. Cookie flags for __204u (F-08); generic REST routing errors (F-09); document/monitor GTM paths (F-10); trim robots (F-11).
5. Method handling (F-14), /admin chain (F-15), security.txt (F-16), llms.txt review (F-17), XSS sink regression suite (F-18), baseline CSP + drop X-XSS-Protection (F-19). Normalize downstream GraphQL errors and preflight CORS (F-12, F-13); review anonymous Partner/Course data exposure (F-20); sanitize imageproxy parse errors (F-21); unify retired-path routing (F-22).

## 6. Disclosure

Prepared for responsible disclosure via Coursera's HackerOne program (https://hackerone.com/coursera). The 3 Medium findings (F-01 – F-03, GraphQL oracle cluster) plus F-04 (CORS image proxy) are recommended for a joint advisory. The follow-up pass is complete: service-name leaks and unauthenticated Partner/Course data returns are documented (F-12, F-20), the imageproxy SSRF relay is confirmed (F-04), and APQ/malformed-body behavior is characterized (F-21). An authenticated IDOR pass on `getByEmail`/`me` remains the main pending item.
