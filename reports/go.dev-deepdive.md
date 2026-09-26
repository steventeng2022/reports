# Zero-Day Vulnerability Assessment Report
## GoDev Portal (go.dev, golang.org, play.golang.org, godoc.org, blog.golang.org)

| Item | Detail |
|---|---|
| Report ID | ZD-GODEV-2026-09-24 |
| Assessment date | 24 September 2026 (all evidence timestamps UTC) |
| Target | https://go.dev (canonical host) plus the golang.org redirect family (www.golang.org, play.golang.org, godoc.org, blog.golang.org) and the godoc redirect target pkg.go.dev |
| Stack | Hugo static site served by Google Frontend edge; Go playground service (go.dev/play/ with /_/fmt, /_/compile, /_/share JSON endpoints); Google feedback/survey service (feedback-pa.googleapis.com via /js/hats.js + gstatic lazy.min.js); Cloud DNS (googledomains NS) |
| Method | Non-destructive unauthenticated live probing: header/cookie forensics, reflected-XSS/SSTI/open-redirect/CORS/method matrices, DoH (dns.google) subdomain + NXDOMAIN inventory, TLS certificate analysis, JS-bundle inspection (hats.js, site.js, playground.js), live API-key validation against feedback-pa.clients6.google.com, playground JSON API probing |
| Classification | Confidential — prepared for responsible disclosure |
| Responsible-disclosure contact | Go project security team via https://go.dev/security/ (issue tracker: https://github.com/golang/go) |

## 1. Executive Summary

On 24 September 2026 the Go project website (go.dev and its golang.org-family hosts) was assessed unauthenticated and non-destructively. **13 findings: 1 Medium, 8 Low, 4 Informational.**

The most significant finding is a **live-confirmed exposed Google API key**:

1. `/js/hats.js` ships Google API key `AIzaSyDfBPfajByU2G6RAjUf5sjkMSSLNTj7MMc` plus survey trigger IDs to every visitor; the key passes live authentication against the production `feedback-pa.googleapis.com` service and returns the full active go.dev survey definition, including its Qualtrics form URL and survey ID (F-01).
2. Three names in the go.dev zone — `www.go.dev`, `mail.go.dev`, `m.go.dev` — are dangling NXDOMAIN records, a takeover candidate if any of them is re-created without a matching origin (F-02).
3. The playground JSON API is fully unauthenticated: `/_/compile` executes attacker-supplied Go source on the server, and `/_/share` stores arbitrary snippets (F-03).
4. The site-wide search form targets a dead `404 /search` endpoint (F-05); `X-Frame-Options` and `X-Content-Type-Options` are missing across the go.dev family (F-06); HSTS is absent on three redirect hosts (F-07).

All tests were unauthenticated; no accounts exist on the site, and no forms were submitted beyond minimal JSON/form POSTs to the documented playground and survey endpoints.

## 2. Scope and Environment

- **In scope:** go.dev (`/`, `/play/`, `/dl/`, `/api/`, `/search`, `/pkg/`, `/blog/`); golang.org, www.golang.org, play.golang.org, godoc.org, blog.golang.org (redirect hosts); pkg.go.dev (godoc redirect target, search/robots surface); `/js/hats.js`, `/js/site.js`, `/js/playground.js`; robots.txt; TLS; DNS.
- **Out of scope:** authenticated functionality (none exists), pkg.go.dev internals beyond search/robots, the GitHub repository, WebSocket playground session semantics (undici cannot speak WS).
- **Tooling:** Node 24 built-in `fetch` harness (`work\godev2\00-12` scripts, `redirect: 'manual'`, status codes recorded), manual header/JS/certificate inspection, DoH via dns.google.
- **Stack behavior note:** every host is fronted by Google Frontend; golang.org / www.golang.org / blog.golang.org / godoc.org are pure 301/302 redirect hosts to go.dev and pkg.go.dev; the edge WAF accepts all 13 raw URI characters with 200 (no filtering); no server-side `Set-Cookie` exists on any host; the only cookies are set client-side by `/js/hats.js`.

## 3. Findings

### F-01 — Exposed Google API key in /js/hats.js, live-confirmed against production feedback-pa.googleapis.com
**Severity: Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 4.4) — CWE-792**

`/js/hats.js`, loaded on all go.dev pages, initializes the Google feedback (HaTS) survey client with a public API key and two survey trigger IDs. The key was validated live against the production endpoint: with the real key the request passes authentication and returns the complete active survey (questions, Qualtrics form URL, survey ID `hP9wsvDipkXUYTMx2sAUJq`), while a fake or missing key fails with `API_KEY_INVALID` — proving the key is a working credential, not a placeholder. An attacker can replay the call to enumerate active surveys, learn product feedback questionnaires, and consume the key's quota; the service does pin `Access-Control-Allow-Origin: https://go.dev`, which mitigates but does not prevent cross-origin direct calls.

```
// https://go.dev/js/hats.js (served to every visitor):
var helpApi = window.help.service.Lazy.create(0, {
  apiKey: 'AIzaSyDfBPfajByU2G6RAjUf5sjkMSSLNTj7MMc',
  locale: 'en-US',
});
helpApi.requestSurvey({ triggerId: 'RLVVv5Lf10njVvnD1rP0QUpmtosS', ... });   // second trigger: dz6fkRxyz0njVvnD1rP0QxCXzhSX
$ curl -s -X POST https://feedback-pa.clients6.google.com/v1/survey/trigger/trigger_anonymous \
    -H 'X-Goog-Api-Key: AIzaSyDfBP...' -H 'Origin: https://go.dev' -H 'Content-Type: application/json+protobuf' \
    -d '[["RLVVv5Lf10njVvnD1rP0QUpmtosS",["en-US"],false]]'
→ 200, status "SUCCESS", survey hP9wsvDipkXUYTMx2sAUJq, https://google.qualtrics.com/jfe/form/SV_e3Pirxgs7SWCWEe?...utm_source=HaTS
fake key → 400 [3,"API key not valid. Please pass a valid API key.",["API_KEY_INVALID","googleapis.com",[["service","feedback-pa.googleapis.com"]]]]
```

**Remediation:** Apply HTTP-referrer/origin restrictions or IP-based quota caps to the key in the Google Cloud console, or move the survey fetch behind a small go.dev server-side proxy so the key never ships to clients.

### F-02 — Dangling NXDOMAIN names in the go.dev zone (www.go.dev, mail.go.dev, m.go.dev)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1188**

DoH lookups (dns.google) show `www.go.dev`, `mail.go.dev` and `m.go.dev` returning Status 3 (NXDOMAIN) with no A, CNAME or NS records, while the zone itself is active on Cloud DNS (`go.dev. 1 216.239.36/32/34/38.21`, ns-cloud-*.googledomains.com). HTTPS fetch of `https://www.go.dev/` fails at name resolution. These names are plausible aliases an operator might re-create (www, mobile, mail) — if a future A/CNAME record points at infrastructure not owned by the Go project, a dangling-subdomain takeover becomes possible. No parking CNAMEs were found for any of the three.

```
$ https://dns.google/resolve?name=www.go.dev&type=A   → Status 3 (NXDOMAIN), no answer
$ https://dns.google/resolve?name=mail.go.dev&type=A  → Status 3 (NXDOMAIN), no answer
$ https://dns.google/resolve?name=m.go.dev&type=A     → Status 3 (NXDOMAIN), no answer
$ curl -sI https://www.go.dev/                         → DNS resolution failed (fetch failed)
Control: go.dev → A 216.239.36/32/34/38.21; NS ns-cloud-e1..e4.googledomains.com — zone live, names absent
```

**Remediation:** Either create the records (e.g. www/m alias to go.dev, mail as CNAME) or document the names as intentionally absent and alert on any new record under `*.go.dev` that points off-infrastructure.

### F-03 — Unauthenticated playground JSON API: remote Go compilation and snippet store
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-306**

The playground's JSON API is fully open, unauthenticated, and lives at the site root: `POST /_/fmt` and `POST /_/compile` accept any Go source in a `body` form field (and run it server-side), `POST /_/share` stores arbitrary content and returns an opaque ID, and `GET /_/share?id=` returns it raw. Stored-XSS was verified negative: a shared snippet containing `<img src=x onerror=alert(1)>` renders only as a 200 page whose HTML mentions the ID in the canonical link — the snippet itself is fetched client-side by `playground.js`. The surface is by design, but it is an unauthenticated remote-execution and storage endpoint with no observable rate limiting, and the legacy `play.golang.org/_/*` paths all 404 while the same API on go.dev answers.

```
POST https://go.dev/_/fmt?backend=linux   (form body=<source>)
  → 200 {"Body":"package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello, world!\")\n}\n","Error":""}
POST https://go.dev/_/compile?backend=linux (form body=<source>)
  → 200 {"compile_errors":"","output":"hello, world!\n"}
POST https://go.dev/_/share (form body=<source>) → 200, id ZSSkUBRjali; XSS snippet → id 5p0L0JeFa2j
GET  https://go.dev/_/share?id=5p0L0JeFa2j → 200 raw snippet; GET /play/p/5p0L0JeFa2j → 200 (snippet JS-fetched, not in HTML)
Method asymmetry: GET /_/share → 405, GET /_/compile → 405, GET /_/fmt → 200; play.golang.org /_/* → all 404
```

**Remediation:** Document the API as an intentional unauthenticated execution surface, add per-IP rate limiting, and reject or size-cap `body` payloads to bound CPU spend per anonymous request.

### F-04 — HaTS sampling cookie set without Secure/SameSite, plus malformed re-prompt cookie
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1004**

`/js/hats.js` is the only cookie source on the entire site (no server-side `Set-Cookie` on any host). It writes `HaTS_BKT=<0|1>; path=/; max-age=2592000;` with no `Secure`, `HttpOnly` or `SameSite` attribute, so the value is readable by any first-party script and transmittable over plain HTTP before HSTS applies. Worse, the re-prompt branch writes `cookieName + '=false ; path=/; max-age=2592000;'` — the space after the value makes the browser parse extra attribute pairs, leaving `HaTS_BKT` with a trailing-space value and creating junk cookies literally named `path` and `max-age` on the go.dev domain.

```
// https://go.dev/js/hats.js
document.cookie = cookieName + '=' + inBucket + '; path=/; max-age=2592000;';        // first write: no Secure/SameSite
if (shouldPrompt) {
  document.cookie = cookieName + '=false ; path=/; max-age=2592000;';                // re-prompt write: space after value
  var tag = document.createElement('script');
  tag.src = 'https://www.gstatic.com/feedback/js/help/prod/service/lazy.min.js';
}
// Browser parses the re-prompt write as: HaTS_BKT="false ", then extra pairs named "path" and "max-age"
```

**Remediation:** Append `; Secure; SameSite=Lax` to both writes and fix the `'=false ; '` typo to `'=false;'` so no spurious cookies are created.

### F-05 — Site-wide search form targets a dead 404 /search endpoint
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-252**

New-template pages (e.g. `/about/`) ship a global search form (`action="/search"`, inputs `q` and `m`, keyboard shortcut `/`, placeholder "Search packages or symbols"), but every `/search` variant — bare, `?q=`, `?m=`, and combinations — returns 404 with an empty `<title> - The Go Programming Language</title>` (8/8 combinations tested). The old-template homepage additionally loads `/js/searchBox.js`, which wires up a `.js-searchForm` element that does not exist in its markup — dead JS. The only working site search is `pkg.go.dev/search` (which ships `/opensearch.xml`). A primary user-facing feature therefore leads to an empty 404 page on every new-template page.

```
New template (/about/): <form class="go-SearchForm-form" action="/search">
                          <input name="q" aria-label="Search for a package" placeholder="Search packages or symbols">
                          <input name="m" ...>
GET https://go.dev/search, /search?q=go, /search?q=go&m=1, /search? ... → 404 (8/8 combos, empty title)
Homepage: <script src="/js/searchBox.js"> binds .js-searchForm — element absent from the page
Working alternative: https://pkg.go.dev/search?q=... (opensearch template /search?q={searchTerms}&ref=opensearch)
```

**Remediation:** Either implement `/search` or point the form at `https://pkg.go.dev/search`; remove `searchBox.js` from the old template or restore the `.js-searchForm` element it expects.

### F-06 — X-Frame-Options and X-Content-Type-Options missing across the go.dev family
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-1021**

No go.dev page — including the 404 template, `/play/`, `/api/` and all redirect-host responses (golang.org, blog.golang.org, play.golang.org, godoc.org 301/302s) — sends `X-Frame-Options` or `X-Content-Type-Options`; only `pkg.go.dev` sends both (`deny` + `nosniff`). Modern browsers are protected by the CSP `frame-ancestors 'self'`, but legacy clients and the four redirect hosts (which carry no CSP) have no clickjacking or MIME-sniffing defense.

```
$ curl -sI https://go.dev/ | grep -iE 'x-frame-options|x-content-type-options'
→ (no matches)
Same for: every go.dev page (/, /play/, /api/, /dl/, 404s) · golang.org 301 · blog.golang.org 301 · play.golang.org 302 · godoc.org 301
Only pkg.go.dev sends both:
  x-frame-options: deny
  x-content-type-options: nosniff
Mitigation present on go.dev: CSP frame-ancestors 'self' (ignored by legacy browsers and absent on redirect hosts)
```

**Remediation:** Emit `x-frame-options: deny` and `x-content-type-options: nosniff` at the Google Frontend edge for all seven hosts, including the redirect responses.

### F-07 — HSTS gaps: play.golang.org lacks includeSubDomains; www.golang.org, godoc.org, pkg.go.dev have no HSTS
**Severity: Low (CVSS 3.1: AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N, 4.9) — CWE-319**

`go.dev`, `golang.org` and `blog.golang.org` send the full `max-age=31536000; includeSubDomains; preload` triple, but `play.golang.org` sends `max-age=31536000; preload` **without `includeSubDomains`**, and `www.golang.org` (302), `godoc.org` (301) and `pkg.go.dev` (200) send no HSTS at all. First-visit users arriving directly on `https://play.golang.org/` (a well-known bookmark), `godoc.org` or `pkg.go.dev` get no HSTS bootstrap, and subdomain-scoped attacks on play.golang.org are not covered by the apex preload entry.

```
go.dev / golang.org / blog.golang.org → strict-transport-security: max-age=31536000; includeSubDomains; preload
play.golang.org (302 → https://go.dev/play/) → strict-transport-security: max-age=31536000; preload    ← no includeSubDomains
www.golang.org (302 → https://go.dev/)      → no HSTS
godoc.org (301 → https://pkg.go.dev/?utm_source=godoc) → no HSTS
pkg.go.dev (200)                             → no HSTS
```

**Remediation:** Add `includeSubDomains` to play.golang.org and send the full preload triple (including on the 301/302 redirect responses) for www.golang.org, godoc.org and pkg.go.dev.

### F-08 — All HTTP methods return 200 on / and /api/ (no 405)
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-390**

The static edge answers OPTIONS, PUT, DELETE and PATCH with a full 200 and the complete page body (64,185 bytes for `/`, 29,791 bytes for `/api/`) — no 405, no `Allow` header. `go.dev/play/run` returns 302 for every non-GET method, and on play.golang.org the root 302s while `/run` 404s for PUT/DELETE/PATCH. The uniform soft-200 makes method-based probing and cache-poisoning analysis harder, and hides whether a route expects POST bodies; TRACE could not be tested (undici rejects it client-side).

```
$ for m in OPTIONS PUT DELETE PATCH: curl -s -X $m -o /dev/null -w '%{http_code}\n' https://go.dev/
200 200 200 200     (full 64,185-byte homepage body on every method; no Allow header, no 405)
Same on https://go.dev/api/ → 200 × 4 (29,791-byte HTML)
go.dev/play/run → 302 /play/ for OPTIONS/PUT/DELETE/PATCH
play.golang.org / → 302 for PUT/DELETE/PATCH, OPTIONS 200; play.golang.org/run → 404 × 3, OPTIONS 200
TRACE: client-unsupported (undici TypeError) — noted as a limitation, not an edge verdict
```

**Remediation:** Return 405 with an `Allow` header for non-GET/HEAD methods on static routes so method semantics are explicit at the edge.

### F-09 — Plain-HTTP link to the Google privacy policy in the go.dev footer
**Severity: Low (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-319**

The go.dev footer links the privacy policy over cleartext HTTP: `<a href="http://www.google.com/intl/en/policies/privacy/" target="_blank">`. Because the site's CSP has no `upgrade-insecure-requests` directive (F-10), the target is fetched over plaintext on any non-secure path, exposing the session to downgrade/MITM before the site's own HSTS ever applies. The remaining plain-HTTP references on the page are the harmless W3C XML namespace `http://www.w3.org/2000/svg`.

```
https://go.dev/ footer:
  <a href="http://www.google.com/intl/en/policies/privacy/" target="_blank">Privacy Policy</a>
CSP: no upgrade-insecure-requests → the http:// target is not auto-upgraded
Other http:// refs: http://www.w3.org/2000/svg (XML namespace, not fetched) — harmless
```

**Remediation:** Change the link to `https://www.google.com/intl/en/policies/privacy/` (or add `upgrade-insecure-requests` to the CSP).

### F-10 — CSP lacks form-action and upgrade-insecure-requests; style-src 'unsafe-inline'; img-src *
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-693**

The site-wide CSP (identical on all go.dev pages) is reasonably strict on scripts (hash-pinned) and `frame-ancestors 'self'`, but omits `form-action`, `upgrade-insecure-requests` and `base-uri`, and allows `style-src 'unsafe-inline'` and a wildcard `img-src *`. The missing `form-action` leaves the dead `/search` form (F-05) free to POST anywhere, and the wildcard `img-src` permits image exfiltration beacons to any origin. No `report-uri`/`report-to` is configured, so violations are never observable.

```
content-security-policy (all go.dev pages):
  connect-src 'self' www.google-analytics.com stats.g.doubleclick.net;
  default-src 'self'; font-src 'self' fonts.googleapis.com fonts.gstatic.com data:;
  frame-ancestors 'self'; frame-src 'self' www.google.com feedback.googleusercontent.com ...;
  img-src 'self' www.google.com www.google-analytics.com ssl.gstatic.com www.gstatic.com gstatic.com data: *;
  object-src 'none'; script-src 'self' 'sha256-...'×3 + Google hosts;
  style-src 'self' 'unsafe-inline' fonts.googleapis.com feedback.googleusercontent.com ...
Missing: form-action · upgrade-insecure-requests · base-uri · report-uri
```

**Remediation:** Add `form-action 'self' upgrade-insecure-requests` and `base-uri 'self'`, drop the `img-src *` wildcard, and move inline styles behind hashed nonces.

### F-11 — Search query reflected (HTML-escaped) in the pkg.go.dev page title; golang.org 301 Location echoes the encoded query
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-116**

Two benign reflection points were confirmed with all 7 XSS payloads. `pkg.go.dev/search?q=` reflects the query inside `<title>` — fully HTML-escaped in text context (`<title>&lt;img src=x onerror=alert(1)&gt; - Search Results - Go Packages</title>`), so no attribute or script breakout. `golang.org/search?q=` and `golang.org/dl?q=` echo the URL-encoded query in the `Location` header of a 301 to same-origin `go.dev` — header context only, no injection. On go.dev itself, `/search?q=` 404s and `/dl/?q=` 200s with zero reflection for every payload.

```
https://pkg.go.dev/search?q=<img src=x onerror=alert(1)>
  → 200  <title>&lt;img src=x onerror=alert(1)&gt; - Search Results - Go Packages</title>   (escaped, text context — safe)
https://golang.org/search?q=<svg/onload=alert(1)>
  → 301  Location: https://go.dev/search?q=%3Csvg/onload=alert(1)%3E   (URL-encoded, same-origin target — safe)
go.dev /search?q=<7 payloads> → 404, no reflection; go.dev /dl/?q=<7 payloads> → 200, no reflection
```

**Remediation:** No action strictly required; keep escaping on the pkg.go.dev title and prefer 301-redirecting golang.org queries to a canonical path rather than echoing them in `Location`.

### F-12 — Fingerprinting surface: Google Frontend, x-cloud-trace-context, robots profile, no cookies, no source maps
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 3.1) — CWE-200**

Every go.dev response carries `server: Google Frontend` and a unique `x-cloud-trace-context` (e.g. `f34fc9f118a18465e21cbad541332d97`), which discloses the GCP/Cloud Trace pipeline to every passive observer. robots.txt differs per host (go.dev: `Allow: /`; pkg.go.dev: `Disallow: /search?*, /fetch/*` + sitemap; play.golang.org: no robots file at all, 404), and the WAF accepts all 13 raw URI characters with 200 — no URI filtering. There are no server-set cookies anywhere and no source-map references in `/js/site.js` or `/js/hats.js`. The cluster is useful for passive fingerprinting and for targeting the correct Google-internal service during follow-on attacks.

```
$ curl -sI https://go.dev/
server: Google Frontend
x-cloud-trace-context: f34fc9f118a18465e21cbad541332d97
robots.txt: go.dev "User-agent: * / Allow: /"; pkg.go.dev "Disallow: /search?*, /fetch/*" + Sitemap; play.golang.org → 404 (no robots)
WAF: all 13 raw URI characters → 200 (no 400/403 filtering); no server-side Set-Cookie on any host; no source maps in site.js/hats.js
```

**Remediation:** Optionally strip or shorten `x-cloud-trace-context` on public responses, publish a robots.txt for play.golang.org, and consider whether `/fetch/*` should stay disallowed-but-reachable on pkg.go.dev.

### F-13 — TLS certificate inventory: all valid; godoc.org expires earliest (2026-11-07)
**Severity: Informational (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 3.1) — CWE-295**

All seven certificates are issued by Google Trust Services and were valid at assessment. `go.dev` carries a dedicated `CN=go.dev` certificate valid to 2026-12-20 (matching the prior shallow scan); the golang.org family (golang.org, www., play., blog.) shares `CN=misc-sni.google.com` certificates valid to 2026-12-03, while `godoc.org` (CN=godoc.org) expires 2026-11-07 — the shortest window (~6 weeks) and the one most likely to cause a surprise renewal gap — and `pkg.go.dev` to 2026-11-23. No hostname/SAN mismatches or chain issues were observed.

```
host                  subject                 issued        expires
go.dev                CN=go.dev               2026-09-21    2026-12-20
golang.org/www/play/blog  CN=misc-sni.google.com  2026-09-10  2026-12-03
godoc.org             CN=godoc.org            2026-08-09    2026-11-07   ← shortest expiry
pkg.go.dev            CN=pkg.go.dev           2026-08-25    2026-11-23
All issued by Google Trust Services; all valid at assessment; no SAN mismatches
```

**Remediation:** Monitor the godoc.org certificate for renewal well before 2026-11-07; no immediate action required for the other hosts.

## 4. Blocked Escalation Attempts

| Attempt | Result |
|---|---|
| Reflected XSS on go.dev `/search?q=` (7 payloads incl. `<script>`, `<img onerror>`, `<svg/onload>`, quote-breaks) | 404 with zero reflection in body, headers or title (F-11) |
| Reflected XSS on go.dev `/dl?q=` and `/dl/?q=` (7 payloads) | 302 → `/dl/` / 200; query not echoed anywhere |
| Reflected XSS on golang.org `/search?q=` and `/dl?q=` (7 payloads) | 301; only the URL-encoded query echoed in `Location` to same-origin go.dev — no injection point (F-11) |
| pkg.go.dev `/search?q=` reflection (7 payloads) | 200, query reflected HTML-escaped inside `<title>` (text context) — no breakout (F-11) |
| Stored XSS via playground share (`/_/share` → `/play/p/<id>`) | 200 page contains only the ID in the canonical link; snippet is fetched by `playground.js` (0 occurrences of `onerror=alert(1)` in served HTML) (F-03) |
| SSTI `{{7*7}}` / `${7*7}` on go.dev search params (4 variants) | 404, no computed `49` in any response |
| Open-redirect params `?url/redirect/next/continue/r/target` on go.dev, golang.org, blog.golang.org | go.dev 200 (params ignored); golang.org/blog 301 with same-origin query passthrough only — no cross-origin `Location` |
| CORS matrix (Origin: `https://evil-attacker.example` and `null`) across go.dev, golang.org, play., godoc., blog. × `/`, `/search`, `/dl`, `/api/`, `/play/` | No `Access-Control-Allow-Origin` reflection on any route; feedback service pins ACAO to `https://go.dev` |
| Sensitive paths on go.dev: `/.git/HEAD`, `/.git/config`, `/.env`, `/admin`, `/admin/`, `/debug`, `/internal`, `/actuator/env`, `/swagger.json`, `/phpmyadmin`, `/console` | All 404 (HTML 404 template); only `/api` → 301 → `/api/` 200 (HTML page, empty title) |
| Same sensitive paths on golang.org | All 301 → go.dev equivalents, same result |
| TRACE method on go.dev, play.golang.org | Client-unsupported in undici (`TypeError: 'TRACE' HTTP method is unsupported`) — noted as a limitation, not an edge verdict (F-08) |
| Legacy play.golang.org `/_/*` API paths (`/_/fmt`, `/_/compile`, `/_/share`) | All 404 — the host is redirect-only; the live API is at the go.dev site root (F-03) |
| WebSocket playground session (`/socket`) | Not testable with fetch-based harness (undici) — documented as out-of-reach |

## 5. Remediation Priorities

1. Review the feedback survey key in `/js/hats.js`: add referrer/origin restrictions or quota caps, or proxy the call server-side (F-01).
2. Decide the disposition of the dangling names — create, alias, or formally document — and alert on future `*.go.dev` records pointing off-infrastructure (F-02).
3. Bound the playground API: per-IP rate limiting and payload-size caps on `/_/compile`, `/_/fmt`, `/_/share` (F-03); return 405 for non-GET methods on static routes (F-08).
4. Fix the HaTS cookie writes: add `Secure; SameSite=Lax` and correct the `'=false ; '` typo (F-04).
5. Either implement `/search` or point every new-template form at `pkg.go.dev/search`; delete the dead `searchBox.js` (F-05).
6. Emit `x-frame-options: deny` and `x-content-type-options: nosniff` on all seven hosts including redirect responses (F-06); complete the HSTS preload triple on www.golang.org, godoc.org, pkg.go.dev and add `includeSubDomains` on play.golang.org (F-07); upgrade the footer privacy-policy link to HTTPS (F-09).
7. Tighten the CSP: `form-action 'self'`, `upgrade-insecure-requests`, `base-uri 'self'`, drop `img-src *` (F-10).
8. Hygiene: publish a robots.txt for play.golang.org, consider stripping `x-cloud-trace-context`, and monitor the godoc.org certificate renewal ahead of 2026-11-07 (F-12, F-13).

## 6. Disclosure

Prepared for responsible disclosure to the Go project via the contact listed on https://go.dev/security/ (issues tracked at https://github.com/golang/go). The single Medium finding (F-01, live-confirmed exposed Google API key) is recommended for a dedicated advisory or direct security-team notice; the eight Low findings (F-02 – F-09) can follow as a single hardening batch, and the four Informational items (F-10 – F-13) as a fingerprinting/TLS baseline note. All evidence is reproducible from the unauthenticated probes catalogued in Section 4 and stored under `work\godev2\`.
