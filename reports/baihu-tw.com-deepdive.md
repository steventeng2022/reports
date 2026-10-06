# Penetration Test Report — https://baihu-tw.com

| | |
|---|---|
| **Target** | https://baihu-tw.com (personal website, React SPA + Node/Express API behind Cloudflare → nginx) |
| **Focus** | `/admin/traffic` admin panel + full public API surface |
| **Test window** | 2026-10-05 02:03 UTC – 16:45 UTC (recon from 02:03; bundle capture 12:35; active API/login testing 13:30–16:42; Taipei: Oct 5 10:03 – Oct 6 ~00:45) |
| **Type** | Black-box, single vantage IP, authenticated-where-possible (no valid credentials obtained) |
| **Tools** | curl 8.x, PowerShell 5.1, manual JS bundle analysis (487 KB `index-B1Bq-rjO.js`) |
| **Report date** | 2026-10-06 (Asia/Taipei) |

---

## 1. Executive summary

The site is a well-hardened personal site: strict CSP on HTML and `default-src 'none'` on API responses, no CORS headers, `X-Frame-Options: DENY` + `frame-ancestors 'none'`, nosniff, TLS 1.2/1.3 only, an Origin check that rejects all mutating requests (including login) from the wrong origin, and a uniform 401 that prevents user enumeration.

The most important finding of this engagement is a **live regression (first observed 15:46:48 UTC Oct 5; still active at report time)**: every request with `Content-Type: application/json` and a **non-empty JSON body returns HTTP 500** on *every* route and method. The React SPA sends JSON for login, for the traffic beacon, and for all admin CRUD — so **admin login, the /admin/traffic view-counter, and the entire admin panel were effectively broken for the entire observation window 15:46:48→16:39:12 UTC Oct 5 and were still broken at report time (last confirmed-healthy beacon: 13:40:24 UTC)**. The server-side login logic itself is still intact (urlencoded/multipart login bodies still return a normal 401), which isolates the fault to the JSON body-parsing path. The regression appeared **without a process restart** (uptime deltas across the 55-minute span match wall-clock time, implying a single ~9.6-day-old process), suggesting a config/data change or a hot code reload around 15:46 UTC Oct 5.

Secondary findings: the site is fully served over **plain HTTP with no HSTS and no 301** (MEDIUM); `/api/server-status` is publicly exposed and leaks uptime + last-activity (LOW); the login rate limiter (≈5 attempts per ≈15-minute window) counts *every* POST including junk and 500s, while 429s are not counted — noisy neighbors on the same IP can delay a legitimate login by ~15 minutes (LOW); the unauthenticated beacon endpoint has no rate limit (LOW); Express default 404 pages and OPTIONS `Allow` headers leak the full route/method map (INFO); `nginx/1.31.5` is fingerprinted from 405 pages (INFO).

No valid credentials were obtained (~30 login attempts across 15 distinct password guesses, all 401). Post-auth vectors identified in the JS bundle (stored XSS via `allowDangerousHtml`, `backgroundUrl` image fetch/injection, upload validation, IDOR) are documented in §5 as **unverified, requiring credentials**.

### Findings summary

| ID | Severity | Finding |
|----|----------|---------|
| M-1 | MEDIUM | Global 500 on any non-empty JSON body — admin login, beacon, all admin CRUD broken for the observation window (still active at report time) |
| M-2 | MEDIUM | Full site served over plain HTTP; no HSTS, no HTTP→HTTPS redirect |
| L-1 | LOW | `/api/server-status` public: uptime, lastActivity; process uptime + counter mismatch exposed |
| L-2 | LOW | Login rate limiter: ≈5 attempts / ≈900 s window; counts junk + 500s; 429s uncounted; scope (per-IP vs global) inconclusive |
| L-3 | LOW | Unauthenticated beacon `POST /api/analytics/view` has no rate limit (pre-regression) |
| I-1 | INFO | Express default 404 HTML leaks route names + allowed methods (`Cannot DELETE /api/articles`) |
| I-2 | INFO | OPTIONS on API routes leaks `Allow` headers (route/method enumeration) |
| I-3 | INFO | SPA 200-fallback on every unknown path; no `robots.txt` / `security.txt` |
| I-4 | INFO | `nginx/1.31.5` fingerprint on 405 pages; Cloudflare in front; mismatched runtime counters (`runtimeDays:13` vs ~9.6 d process uptime) |
| I-5 | INFO | Personal data (GitHub/IG/Discord, bio, school) in public `/api/site-settings` — likely by design |
| I-6 | INFO | `GET /api/auth/me` public, returns 200 `{"authenticated":false}` (also over plain HTTP) |

---

## 2. Findings

### M-1 (MEDIUM) — Global HTTP 500 on every non-empty JSON body; admin login, beacon and all admin CRUD broken for the observation window (still active at report time)

**Observed behavior (re-verified multiple times, 16:14–16:39 UTC Oct 5):**

Any request with `Content-Type: application/json` (case-insensitive; `; charset=utf-8` variants included) and a **non-empty JSON body of any shape** (object, array, string, number) returns:

```
HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8
etag: W/"24-..."
{"message":"Internal server error."}
```

on **every** tested route and method:

| Request | Result |
|---|---|
| `POST /api/auth/login` `{"username":"baihu","password":"..."}` | 500 |
| `POST /api/auth/me` (JSON body) | 500 |
| `POST /api/analytics/view` `{"page":"home"}` | 500 |
| `POST /api/stats` (JSON body) | 500 (route exists for GET only) |
| `GET /api/stats` **with** JSON body `{"x":1}` | 500 |
| `GET /api/articles`, `GET /api/site-settings`, `GET /api/music` **with** JSON body | 500 |
| `POST /api/articles` `{"title":"t"}` | 500 |
| `POST /api/analytics/view` body `["page"]` (array) | 500 |
| `POST /api/analytics/view` body `"hi"` (string) | 500 |
| `POST /api/analytics/view` body `42` (number) | 500 |

**What does NOT crash (same routes, 16:30 UTC):**

| Request | Result |
|---|---|
| `POST /api/analytics/view` body `{}` (empty object) | 400 `{"message":"Invalid page."}` |
| `POST /api/analytics/view` 0-byte body, CT json | 400 `{"message":"Invalid page."}` |
| `POST /api/analytics/view` CT `application/x-www-form-urlencoded` `page=home` | 400 `Invalid page.` |
| `POST /api/analytics/view` CT `multipart/form-data` field `page=home` | 400 `Invalid page.` |
| `POST /api/analytics/view` CT `text/plain` `hello` | 400 `Invalid page.` |
| `POST /api/analytics/view` CT `application/vnd.api+json` `{"page":"home"}` | 400 `Invalid page.` (not parsed as JSON) |
| `POST /api/analytics/view` CT `text/json` `{"page":"home"}` | 400 `Invalid page.` (not parsed as JSON) |
| `POST /api/auth/login` urlencoded `username=baihu&password=...` | 401 `Invalid username or password.` |
| `POST /api/auth/login` multipart `username=baihu` | 401 |

So the crash is triggered specifically when the JSON content-type parser produces a **non-empty** body. The handler logic behind those routes is otherwise healthy (clean 400/401/204 paths via non-JSON channels).

**Impact**

1. **Admin login is broken.** The SPA's login form sends `application/json`. The server-side credential check still works (urlencoded logins reach it and return 401), so the admin is locked out purely by the transport-layer crash. A human can log in only by crafting a non-JSON request (e.g. urlencoded), which the browser app does not do.
2. **The `/admin/traffic` beacon is broken.** The traffic page posts `{"page":"..."}` to `/api/analytics/view`; it now 500s, so view counts are lost for every visitor since ~15:47 UTC Oct 5.
3. **All admin CRUD is broken.** Articles, site-settings, music order, friends — every admin save/put/delete the SPA issues as JSON 500s.
4. **GET routes with a JSON body also crash**, so even read endpoints misbehave when a client (or proxy/tool) attaches a JSON body.
5. **Error handling:** the 500 path returns a generic JSON message (good), but the fact that *every* route is affected indicates a shared middleware/parser fault rather than per-route bugs.

**Timeline**

| Time (UTC, Oct 5) | Event |
|---|---|
| 13:40:24 | Last healthy beacon: `POST /api/analytics/view` → **204** (valid JSON body accepted) |
| 15:46:48–49 | First observed 500s: JSON-body matrix t1–t7 (incl. malformed-JSON login → 500; empty Origin → 403) + 10 beacons → 500 |
| 15:47:21 | First observed 500 on the beacon (same request shape as the 13:40:24 204) |
| 15:47:21–16:39:12 | Regression continuously confirmed (all shape/CT probes in the matrices above) |
| ≥ 16:39:12 | Still active at last re-check (~1 h after first observed 500; ~3 h after last healthy beacon) |

**Process/infrastructure analysis (no restart detected)**

`/api/server-status` (public) uptime readings:

| Time (UTC) | uptimeSeconds | implied process start |
|---|---|---|
| 15:43:36 | 823656 | 2026-09-26 02:56:00 |
| 16:00:36 | 824676 | 2026-09-26 02:56:00 |
| 16:14:12 | 825491 | 2026-09-26 02:56:01 |
| 16:39:12 | 826992 | 2026-09-26 02:56:00 |

Uptime deltas match wall-clock deltas to within ±1 s across the full 55-minute span (15:43:36→16:00:36: 1020 s vs 1020 s; 16:00:36→16:14:12: 816 s vs 815 s; 16:14:12→16:39:12: 1500 s vs 1501 s): the API was served throughout by **one process (or identically-timed workers) started 2026-09-26 02:56:00 UTC and never restarted** — ~9.6 days before the regression. The ~15:46 behavior change was therefore **not a deploy/restart**: it is most plausibly a config/data change picked up by running processes, a hot code reload, or a Cloudflare-layer change. (Secondary curiosity: `/api/stats` reports `runtimeDays: 13`, a counter that disagrees with the ~9.6 d process uptime.)

**Secondary symptom: beacon page validation now rejects everything via non-JSON channels.** At 13:40 UTC, `{"page":"home"}` returned 204. At 16:24 UTC, urlencoded/multipart `page=home|traffic|about|projects|blog|friends|music|site|overview` **all** return `400 Invalid page.`. So the beacon has two independent faults (JSON-path crash + page whitelist/validation failure) — or the validation depends on data that changed at the same time.

**Recommendations**

- Identify what changed at ~15:46 UTC Oct 5 (files on disk, a config the app re-reads per request, CF ruleset) — the process was not restarted.
- Wrap/fix the JSON body-parsing middleware (the crash site); add integration tests: non-empty JSON body on GET and POST routes must not 500.
- Consider accepting `application/x-www-form-urlencoded` in the login handler and beacon as a resilient fallback (it already works server-side).
- Re-validate the beacon page whitelist against the SPA's actual page identifiers.
- Alert on 5xx rate for `/api/*` — a single 500 would have flagged this; the condition persisted across the whole observation window (15:46:48→16:39:12 UTC) and beyond, with no process restart in between.

---

### M-2 (MEDIUM) — Full site served over plain HTTP; no HSTS, no redirect

**Evidence (16:14:12 & 16:39 UTC):**
- `http://baihu-tw.com/` → **200** full HTML page (served plaintext, no redirect to HTTPS).
- `http://baihu-tw.com/api/auth/me` → **200** `{"authenticated":false}` over plaintext.
- No `Strict-Transport-Security` header on any captured response (HTML page header block captured 16:14:12: CSP, nosniff, XFO, permissions-policy, referrer-policy all present — HSTS absent).
- No HTTP→HTTPS 301 anywhere tested.

**Risk:** a first-visit or cleartext-redirected client stays on HTTP; cookies (if set without `Secure`) and any credentials in transit are exposed to on-path downgrade/MITM. The API returns session state (`authenticated` flag) in cleartext.

**Recommendations:** 301 all `http://` to `https://`; add `Strict-Transport-Security: max-age=31536000; includeSubDomains` once all subresources load over HTTPS; consider `upgrade-insecure-requests` in CSP.

---

### L-1 (LOW) — `/api/server-status` publicly exposed

`GET /api/server-status` (no auth) returns:

```json
{"status":"online","uptimeSeconds":826992,"lastActivity":"2026-10-04T23:47:41.307Z"}
```

Leaks server uptime (enables the no-restart analysis in M-1), the last recorded user activity timestamp, and a liveness oracle. Reachable over plain HTTP too (M-2).

**Recommendation:** require auth, or move to `/api/admin/...`, or drop `lastActivity`/`uptimeSeconds` from the public payload.

### L-2 (LOW) — Login rate limiter: ~5 attempts per ~15-minute window; junk and 500s count, 429s do not

Characterized empirically from `retry-after` values (all times UTC, Oct 5; the header is exact — see Appendix C for the data table):

- A **~900 s (15 min) window**, anchored to the **first login attempt after the previous window ends**, admits **~5 counted attempts**; further attempts in the window get 429 with `retry-after` = seconds until the window ends.
- **Every** POST to `/api/auth/login` that passes the limiter is counted — any username, any Content-Type, any result (401 **and** 500). A single junk/garbage POST consumes 1/5 of the budget.
- **429 responses are neither counted nor extend the window** (verified: a 429 probe reported the pre-existing window end unchanged).
- The window length/scope is **inconclusive between per-IP and global**: two observed windows match exactly 900 s anchored to our own first attempt; a third window's end (16:35:43) does not match any of our known anchor attempts under a strict 900 s model, consistent with an unknown third party (e.g., the site owner) also consuming a shared window.

**Impact:** an on-path or co-located attacker (or even the site owner hammering a broken login) can consume the 5-attempt budget and delay a legitimate login by up to ~15 minutes. No per-username throttling exists, and the limiter does not differentiate success/failure, so repeated genuine login attempts during a broken-deploy window (as in M-1) can exhaust it.

**Recommendations:** count only *failed* auth attempts; key the limiter per IP+username or per session token; consider exponential backoff per username; document the window in the 429 body (`retry-after` is already good).

### L-3 (LOW) — Unauthenticated beacon `POST /api/analytics/view` has no rate limit

Before the M-1 regression, rapid-fire beacons (`{"page":"..."}`) returned 204 without limit (10+ in a row at 13:39–13:40 UTC; the *login* endpoint was rate-limiting in the same window, proving the limiter is route-scoped, not global). Any client can inflate the traffic statistics unboundedly; `page` values are validated against a whitelist, so the impact is metric inflation (and, during M-1, 500 storms) rather than data leakage.

**Recommendation:** apply a light per-IP rate limit (e.g., 30/min) to the beacon; deduplicate by IP+page+minute.

### I-1 (INFO) — Express default 404 pages leak the route/method map

Unknown **API** paths return Express's built-in HTML error page, e.g.:

```html
<pre>Cannot GET /api/auth/login</pre>
<pre>Cannot DELETE /api/articles</pre>
<pre>Cannot POST /api/stats</pre>
```

This confirms route existence **and** which HTTP methods are registered (the verb in the message). Captured routes include `/api/auth/login`, `/api/articles`, `/api/stats`, `/api/server-status`, etc.

**Recommendation:** a custom JSON 404 for `/api/*` (e.g., `{"message":"Not found."}`).

### I-2 (INFO) — OPTIONS leaks `Allow` on API routes

`OPTIONS /api/articles` → `200` with `allow: GET, HEAD, POST`; `OPTIONS /api/admin/analytics` → `allow: GET, HEAD`. Complements I-1 for method enumeration without triggering 404 pages.

**Recommendation:** return a minimal 204 with `Allow` only for genuinely exposed methods, or a generic 200 without `Allow` on unknown routes.

### I-3 (INFO) — SPA 200-fallback on every unknown path; no robots.txt / security.txt

Every unknown **non-API** path (including `/robots.txt`, `/security.txt`, `/favicon.ico`, deep random paths) returns **200** with the SPA index. Crawlers therefore see an infinite 200 surface; there is no `robots.txt` or `security.txt`.

**Recommendation:** serve a real `robots.txt`/`security.txt` (or 404 them); optionally 404 for unknown `/admin/*` paths to reduce accidental index serving.

### I-4 (INFO) — Stack fingerprinting: `nginx/1.31.5`, Cloudflare, Express; mismatched runtime counters

- 405 error pages for static routes (e.g., `POST /favicon.ico`, `PUT /`, `POST /assets/index-B1Bq-rjO.js`) contain `<center>nginx/1.31.5</center>` (re-verified live 16:42:16 UTC; `Server: cloudflare` on all responses).
- Express JSON error shape + `etag` on error responses identifies the Node layer.
- `/api/stats` advertises `runtimeDays: 13` while `/api/server-status` uptime implies ~9.6 days — two different "runtime" counters are publicly exposed (see M-1 analysis).

**Recommendation:** hide the nginx version on error pages (`server_tokens off;`), and reconcile the two runtime counters or hide one.

### I-5 (INFO) — Personal data in public `/api/site-settings` (likely by design)

`GET /api/site-settings` (no auth) exposes: site name, a biography mentioning a **school transition (HCSH → FJU)**, experience lines (FRC), and social handles (GitHub `baihufox3210`, Instagram `baihu3210`, Discord ID) also visible in the bundle. For a personal site this is presumably intended; noting it for OSINT/correlation purposes.

### I-6 (INFO) — `GET /api/auth/me` is public

Returns `200 {"authenticated":false}` without auth (and over plain HTTP per M-2). Harmless alone, but combined with M-2 it discloses session state in cleartext, and the endpoint's existence is an extra probe target.

---

## 3. Good practices (things that held up under testing)

- **CSP:** HTML page — `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`. All API responses — `default-src 'none'; media-src 'self'; frame-ancestors 'none'` (strong: no inline scripts, no cross-origin connections).
- **Headers:** `x-content-type-options: nosniff`, `x-frame-options: DENY`, `referrer-policy: strict-origin-when-cross-origin`, `permissions-policy: camera=(), microphone=(), geolocation=()` on every response.
- **No CORS headers** on any API response → cross-origin API access requires the victim's browser to be on-origin; no `Access-Control-Allow-Origin` at all.
- **Origin check on all mutating routes, including login:** `POST /api/auth/login` without `Origin: https://baihu-tw.com` → 403; **duplicate** Origin headers → 403; `Referer` alone is **not** trusted. This applies to login, articles, site-settings, music, friends, admin routes — a solid CSRF posture for a cookie-auth app.
- **Uniform 401** `{"message":"Invalid username or password."}` — no user enumeration (username existence indistinguishable from wrong password).
- **TLS 1.2/1.3 only** (no legacy protocol/cipher issues observed); Cloudflare front with HTTP/3 advertised.
- **No directory listing** on `/uploads/` or static roots; uploaded assets served with correct MIME types.
- **`Cache-Control: no-store`** on API responses; `ETag`/`Last-Modified` hygiene on static assets.
- The rate limiter does exist on the most sensitive endpoint (login) and returns a correct `retry-after`.

## 4. Prioritized recommendations

1. **Fix the JSON body 500 regression (M-1)** — it is breaking the product's admin flow right now. Find what changed ~15:46 UTC Oct 5 without a restart; fix the JSON parsing middleware; add a regression test (non-empty JSON body on GET+POST routes must not 500).
2. **HTTPS-only: 301 + HSTS (M-2)** — cheap, standard, eliminates the cleartext session/credential exposure.
3. **Restrict `/api/server-status` (L-1)** and reconcile the `runtimeDays` counter (I-4).
4. **Tune the login limiter (L-2)** — count failed attempts only, key per IP+username; rate-limit the beacon (L-3).
5. **Custom 404 for `/api/*`, trim OPTIONS `Allow` (I-1/I-2), real `robots.txt`/`security.txt` (I-3), `server_tokens off` (I-4).**
6. When credentials are available, verify §5 (stored XSS, `backgroundUrl`, uploads, IDOR) and cookie flags (`HttpOnly/Secure/SameSite`).

## 5. Unverified — requires valid credentials

Identified from the production JS bundle (`/assets/index-B1Bq-rjO.js`, 487 KB) but not confirmable without an authenticated session:

1. **Stored XSS via article Markdown (`allowDangerousHtml: true`).** The bundle configures react-markdown with `allowDangerousHtml:!0`, so raw HTML in an article's markdown renders on the public site. The CSP (`script-src 'self'`, no `unsafe-inline`) blocks classic `<img onerror=...>` inline handlers, so a working payload would need DOM-clobbering, `<base>`/`<link>` tricks, or a blocked-but-bypassable inline path. If any XSS fires, it runs same-origin with cookies → it can call the admin API (`connect-src 'self'`, `credentials: 'include'`) for **session takeover / admin read**. Test: as admin, save an article with crafted HTML, open the public article page.
2. **`backgroundUrl` from public `/api/site-settings` → client-side fetch of an arbitrary URL.** The preloader does `new Image().src = backgroundUrl` (arbitrary cross-origin GET from every visitor's browser — client-side SSRF / tracking) and applies `style.backgroundImage = 'url("'+backgroundUrl+'")'` (quote-breakout → CSS injection, weaker than the attribute case but real). A 32×32 canvas readback of the background was also found. Test: set `backgroundUrl` to `https://attacker.example/pixel` and to a CSS-payload value; observe requests from a clean browser.
3. **Upload validation.** Music upload sends `FormData` with `tracks` (files) + `fileNames` (JSON array); the client filters `*.mp3` **by filename only**. Article save sends `coverImage` (file), `document`, `removeDocument`, `coverImagePosition`, `coverImageScale`. Server-side checks on MIME type, extension, size, and content (an 8 MB constant `8388608` appears in the bundle but only inside a bit-twiddle library — the real limit is unverified) need testing: upload `.mp3`-named HTML/SVG/PDF, oversized files, double extensions.
4. **IDOR on `:id` routes.** Unauthenticated `GET /api/articles/:id`, `/api/music/:id`, etc. return 401 (verified), but cross-user authorization on update/delete and on admin `:id` routes is untestable without a second account.
5. **Session/cookie hardening.** Login is cookie-based; cookie flags (`HttpOnly`, `Secure`, `SameSite`, `Path`), expiration, logout behavior, and session rotation on login are unverified (no successful login obtained).
6. **Admin-only surface.** `GET /api/admin/analytics`, `/api/admin/activity`, `/api/admin/site-settings`, `/api/admin/friends`, `/api/admin/music/order` (OPTIONS shows the method maps) — behavior, rate limiting, and pagination/parameter handling unverified.

---

## Appendix A — Endpoint matrix & layering

Unauthenticated observations from a single vantage IP, 2026-10-05 UTC (scope: Appendix F).

### A.1 Endpoint behavior matrix

| Endpoint | Method(s) | Observed result (Oct 5) | Notes |
|---|---|---|---|
| `/` | GET | 200 | HTML `Last-Modified` flipped at 08:33:28 (deploy); bundle `index-B1Bq-rjO.js` (~487 KB); also served over plain HTTP (M-2) |
| any SPA path (e.g. `/admin/traffic`, `robots.txt`, `security.txt`) | GET | 200 | SPA fallback; `robots.txt`/`security.txt` served as the 502-byte SPA shell, not real files (I-3) |
| `/assets/*` | GET | 200 | static assets; `POST /assets/bundle.js` → 405 (nginx) |
| `/uploads/*` | GET | 200 | e.g. `fdf22590-….mp3` — 9,437,189 B with ZIP magic bytes; no directory listing |
| `/api/auth/login` | POST | 403 (no Origin) → 401 (urlenc/multipart/textplain) → 429 (rate-limited) → 500 (JSON body, post 15:46:48) | origin check precedes the limiter; full ledger in Appendix B, limiter model in Appendix C |
| `/api/auth/me` | GET | 200 `{"authenticated":false}` | also over plain HTTP; JSON body on GET → 500 (M-1) |
| `/api/auth/logout` | POST | 200 | succeeds unauthenticated (no session to clear) |
| `/api/analytics/view` | POST | 204 (pre 15:46:48) / 500 (JSON body) / 400 `Invalid page.` (`{}`, 0 B, urlenc, multipart, textplain) | unauthenticated beacon; unthrottled (L-3) |
| `/api/articles` | GET / POST / DELETE | 200 (list) / 401 / 404 | DELETE on the collection → 404 at 15:43:36 and 16:42:17 |
| `/api/articles/:id` | GET | 401 (UUID id) / 404 (e.g. `/1`) | `:id` is a UUID; unknown UUID → 401 (IDOR unverified, §5.4) |
| `/api/site-settings` | GET | 200 | public: `siteName`, `bio`, `experience`, `backgroundUrl` (I-5) |
| `/api/music` | GET | 200 | 1 track, `createdAt 2026-10-04T05:28:19Z` |
| `/api/stats` | GET / POST | 200 / 404 `Cannot POST` (non-JSON) → 500 (JSON body) | payload: `articleCount:1`, `categoryCount:1`, `tagCount:3`, `totalWords:18`, `runtimeDays:13`, `lastActivity:2026-10-04` (I-4) |
| `/api/server-status` | GET | 200 | public uptime + `lastActivity` (L-1) |
| `/api/admin/analytics`, `/api/admin/activity` | any | 401 | |
| `/api/admin/site-settings` (PUT/PATCH), `/api/admin/friends` (POST/DELETE), `/api/admin/music/order` (PUT) | mutating | 401 (no body) / 500 (JSON body) | admin CRUD; the 500s are M-1 |
| `PATCH /api/nope-xyz` | PATCH | 404 Express `Cannot PATCH` | |
| `GET /api/auth/login` | GET | 404 `Cannot GET` | (I-1) |
| `POST /favicon.ico`, `PUT /` | — | 405 nginx/1.31.5 | origin nginx (I-4); 16:42:16–17 (fp1–fp3) |
| `TRACE /` | TRACE | 405 Cloudflare edge (`CF-RAY: -`, 15:43:36) | terminated at the CF edge, never reached origin |

### A.2 OPTIONS `Allow` map

| Endpoint | `allow` | Observed |
|---|---|---|
| `/api/analytics/view` | `POST` | 02:03:13 session log; re-confirmed 13:44:07 (gch) |
| `/api/admin/analytics` | `GET, HEAD` | 02:03:13 session log; 15:02:27 (opt); 15:43:37 (verify1) |
| `/api/articles` | `GET, HEAD, POST` | 15:43:37 (verify1); 16:14:12 (s2_8) |

### A.3 Layering

1. **Cloudflare edge** — `Server: cloudflare` on all responses; HTTP/3; CF-RAY pops rotate TPE/HKG/NRT/SEA/KIX; the edge answers some methods itself (`TRACE` → 405, `CF-RAY: -`).
2. **Origin nginx/1.31.5** — its own 405 bodies on non-API paths (`POST /favicon.ico`, `PUT /`, `POST /assets/bundle.js`).
3. **Express app** — HTML `Cannot GET/POST/PATCH` 404s; JSON 400/401/403/500 with `etag`.

Note: `DELETE /api/articles` reached the origin Express both times (15:43:36, 16:42:17) while `TRACE /` was terminated at the CF edge — method handling is per-layer; no functional impact on the API was observed from this vantage.

## Appendix B — Login attempt ledger

Total: **67 saved requests + ~12 unsaved ≈ 79 requests** to `POST /api/auth/login`; **zero successes** (every outcome was 403/401/429/500). The exec summary’s “~30 login attempts” refers to the 401/500 subset (28 saved) — consistent with “~”.

### B.1 403 — origin rejected (14 saved)

| File | Time (UTC) | Notes |
|---|---|---|
| o2 | 13:33:37 | no Origin header |
| last_body | 13:34:35 | |
| l(1)–l(8) | 13:35:12–22 | origin/Content-Type matrix; 403s during active window W1 prove the origin check precedes the rate limiter; l(2)/l(4)/l(8) include CF-405 side-entries |
| d1b–d3b | 14:30:56 | |
| t6 | 15:46:49 | empty Origin; body `{"message":"Request origin is not allowed."}` |

### B.2 429 — rate-limited (25 saved)

| File | Time (UTC) | `retry-after` (s) | Window |
|---|---|---|---|
| v1 | 13:38:22 | 417 → 13:45:19 | W1 |
| r1 | 13:39:00 | 379 → 13:45:19 | W1 |
| re1–re4 | 13:40:21–23 | 298/297/297/296 → 13:45:19 | W1 |
| l3b | 13:48:56 | (not saved) | post-W1-end anomaly |
| cb3 | 14:50:33 | (not saved) | post-window anomaly |
| f1–f4 | 16:03:13 | — (window still open) | W2 |
| g2_1–g2_4 | 16:11:35–41 | — (window still open) | W2 |
| rateprobe | 16:12:02 | 281 → 16:16:43 (clean 900 s) | W2 |
| g3_1–g3_4 | 16:16:24–31 | — (window still open) | W2 |
| g5_1–g5_4 | 16:32:31–38 | 212/210/208/205 → 16:35:43/44 | W3 |

### B.3 401 — invalid credentials (21 saved; identical 43-byte body, 200–330 ms, no enumeration signal)

| File | Time (UTC) | Credential |
|---|---|---|
| lb | 14:02:36 | recon probe |
| tb | 14:03:49 | recon probe |
| d4b | 14:30:56 | text/plain |
| cb | 14:41:08 | |
| cz | 15:22:31 | |
| cb4 | 15:32:17 | |
| b7 | 15:54:37 | text/plain |
| d4 | 16:00:37 | |
| e1–e3 | 16:01:41–42 | baihu/WrongPass123! (urlenc); zzprobe106c/x (urlenc); baihu/WrongPass123! (multipart) |
| rateprobe2 | 16:18:58 | zzratecheck2 |
| g4_1–g4_4 | 16:20:56–21:03 | |
| fin0–fin4 | 16:38:00–07 | zzrate3 probe; baihu/Baihu2026; baihu/baihufox; admin/Baihu@3210; fox/3210 |

### B.4 500 — JSON-body regression (7 saved; all counted by the limiter)

| File | Time (UTC) | Notes |
|---|---|---|
| t7 | 15:46:49 | malformed JSON |
| a10 | 15:52:40 | |
| b1 / b2 | 15:54:36 | |
| d3 | 16:00:37 | zzprober106 |
| e4 / e5 | 16:01:42–43 | baihu/Baihu@3210; baihu/baihu32103210 |

### B.5 Unsaved attempts (~12)

- user `admin` ×5 — passwords: `admin`, `admin123`, `password`, `123456`, `baihu`
- user `baihu` ×6 — passwords: `baihu3210`, `3210`, `baihu`, `baihu2026`, `BAIHU3210`, `password`
- root/root, test/test
- probe users: `zzfreshuser99`, `zzprober99x`, `zzprober106`, `zzprobe106b`

### B.6 Summary

- Users probed: `baihu`, `admin`, `fox`, `root`, `test`, plus zz-prefixed probes.
- 15+ distinct passwords, including `Baihu@3210`, `baihu32103210`, `32103210`, `Baihu3210!`, `Baihu2026`, `baihufox`, `3210`, plus placeholders (`WrongPass123!`, `zzprobe…`).
- No response-time or body differences between plausible and probe users → no username enumeration.
- No valid credential was ever obtained → the admin surface remains unverified (§5).

## Appendix C — Rate limiter model (empirical)

All observations: `POST /api/auth/login`, single vantage IP, 2026-10-05 UTC.

### C.1 Rules and their evidence

| Rule | Evidence |
|---|---|
| 900 s fixed window, anchored at the first counted attempt after the previous window’s end | W1: six distinct `retry-after` values (417, 379, 298, 297, 297, 296 at 13:38:22→13:40:23) all resolve to exactly 13:45:19; W2: rateprobe (16:12:02, ra=281) resolves to exactly 16:16:43 = anchor 16:01:43 + 900 s |
| Budget = 5 counted attempts — any username, any Content-Type, any result (401 **and** 500) | e1–e5 (16:01:41–43: 401×3 + 500×2) are exactly five, then f1–4 → 429; W3: rateprobe2 + g4_1–4 = five, then g5 → 429 |
| 429 responses neither count nor extend the window | g3_1–4 429’d at 16:16:24–31 (inside W2, before its 16:16:43 end); rateprobe2 then 401’d at 16:18:58 — the window did not extend to 16:16:31+900 |
| 403 (origin check) precedes the limiter | 403s during active W1 (l(1)–8 at 13:35:12–22, while v1/r1/re1–4 were 429ing at 13:38–13:40) |
| Beacons (`POST /api/analytics/view`) are never counted | 204s at 13:40:24 while logins were 429ing at 13:40:21–23 |

### C.2 Observed windows

**W1** — implied anchor 13:30:19 (unrecorded; session start 13:30) → end **13:45:19** (verified by six `retry-after` values, all exactly 900 s after the anchor).

**W2** — anchor 16:01:43 (e1; file mtime 16:01:41, ±2 s) → end **16:16:43** (rateprobe ra=281; clean 900 s). e1–e5 are the five counted; f1–4 429. Note: seven earlier logins (t7 15:46:49, a10 15:52:40, b1/b2 15:54:36, b7 15:54:37, d3/d4 16:00:37) belong to a preceding window whose `retry-after` was never captured; d3/d4 passing at 16:00:37 while e1 opens W2 bounds that window’s end to (16:00:37, 16:01:41).

**W3** — anchors: rateprobe2 16:18:58 (401) + g4_1–4 16:20:56–21:03 (401×4) = five counted → g5 429. Observed end **16:35:43/44** (ra 212/210/208/205) matches neither 16:18:58+900 = 16:33:58 nor 16:20:56+900 = 16:35:56, but **exactly** matches an anchor ~16:20:43 (guess4.ps1 mtime 16:20:41 — an unrecorded request 13 s before g4_1) or a globally shared window.

### C.3 Post-window 429 anomalies

l3b (13:48:56, 3 min after W1’s end) and cb3 (14:50:33) 429’d where a strict per-IP model predicts 401. Scope (per-IP vs global) is therefore **inconclusive from this single vantage** (body L-2).

## Appendix D — Master timeline (2026-10-05, UTC)

| Time | Event |
|---|---|
| 2026-09-26 02:56:00 | API process start (implied from uptime counters; never restarted — M-1) |
| Oct 4 00:00 | article `publishedAt` |
| Oct 4 05:28:19 | music track `createdAt` |
| Oct 4 23:47:41 | `lastActivity` (from `/api/server-status`) |
| 00:31:27 | prior deploy (bundle `index-BxDtU8ue`) |
| 02:03:13 | recon: `/admin/traffic` HTML/headers + OPTIONS map (session 1) |
| 08:33:28 | **deploy** — `Last-Modified` flips; bundle → `index-B1Bq-rjO.js` |
| 12:35:49 | bundle captured (`js_current.js`, 492,467 B) |
| 13:30 | active testing session starts |
| 13:33:36 | o1: beacon 400 |
| 13:33:37 | o2: login 403 (no Origin) |
| 13:34:35 | last_body: login 403 |
| 13:35:12–22 | l(1)–8: origin/Content-Type matrix → 403 (+3 CF-405 side-entries) |
| 13:38:22 | v1: 429, retry-after 417 |
| 13:39:00 | r1: 429, retry-after 379 |
| 13:40:21–23 | re1–4: 429, retry-after 298/297/297/296 — all resolve to 13:45:19 (W1 end) |
| 13:40:24 | **last healthy beacon: 204** |
| 13:41:44 | avb: 400 |
| 13:43:23 | mb: 404 `/api/articles/1` (UUID `:id`) |
| 13:43–48 | mut1: mutation matrix (console-only: admin site-settings/home-profile/friends/projects/music-order, `music/:id` DELETE, `articles/:id` PUT/DELETE, known/random UUID GETs, `../site-settings`, stats PUT, friends DELETE, server-status POST, site-settings PATCH) |
| 13:44:07 | gch: OPTIONS beacon `allow: POST` |
| 13:48:21 | l2b: 404 |
| 13:48:56 | l3b: 429 (post-W1-end anomaly) |
| 14:02:36 | lb: 401 |
| 14:03:49 | tb: 401 |
| 14:04:37 | fb: `/api/music` 200 |
| 14:05:09–33 | plain-HTTP checks: 200, no redirect, no HSTS (http80/h80a/h80b) |
| 14:07:40 | big.mp3 download: 9,437,189 B, ZIP magic bytes |
| 14:07:44 | ub: 100-Continue + 401 |
| 14:30:56 | d1b–d3b: 403 + d4b: 401 |
| 14:41:08 | cb: 401 |
| 14:50:33 | cb3: 429 (anomaly) |
| 15:02:27 | opt: OPTIONS admin/analytics `allow: GET, HEAD` |
| 15:22:31 | cz: 401 |
| 15:32:17 | cb4: 401 |
| 15:43:36–37 | verify1: uptime 823656; DELETE `/api/articles` 404 (Express); TRACE 405 (CF edge); OPTIONS ×2 |
| **15:46:48** | **t1: first observed 500 — JSON-body regression begins** |
| 15:46:49 | t2–t7: stats 500; `/api/` 404; articles 401 no-body; articles 500 JSON; empty-Origin 403; malformed-JSON login 500 |
| 15:46:51 | verify2: 10 beacons → 500 |
| 15:47:21 | beacon_h: first beacon 500 |
| 15:50:46–49 | m1–16: User-Agent matrix (all JSON 500; GET stats 200) |
| 15:52:39–41 | a1–12: admin CRUD 500; admin/analytics 401; articles 200; logout 200 |
| 15:54:36–37 | b1–7: login 500×2; articles 401; logout 200 unauth; music/order 500; admin/activity 401; textplain 401 |
| 15:56:21–22 | c1–7: body-shape sweep |
| 16:00:36–38 | d1–7: uptime 824676; beacon 500; login 500/401; stats 200/500 |
| 16:01:41–43 | e1–5: 401×3 + 500×2 = W2’s five counted |
| 16:03:13 | f1–4: 429 |
| 16:03:58 | getbody g1–5: GET+JSON body 500; POST auth/me 500 |
| 16:11:34–37 | g2_1–4: 429 |
| **16:12:02** | rateprobe: 429, retry-after 281 → 16:16:43 (clean 900 s — W2 end) |
| 16:14:11–13 | s2_1–12: uptime 825491; stats POST {} 404; OPTIONS articles; 200 lists; plain-HTTP me 200 |
| 16:16:23–31 | g3_1–4: 429 + B1 beacon 500 / B2 400 |
| 16:18:58 | rateprobe2: 401 (W3 anchor) |
| 16:20:56–21:03 | g4_1–4: 401 |
| 16:23:23–24 | sh1–6: array/str/num 500; urlenc/textplain/{} 400 |
| 16:24:30–32 | pw1–9: 9 pages urlencoded, all 400 `Invalid page.` |
| 16:25:02 | mp1: multipart probe |
| 16:30:20–21 | ct1–6: JSON case/charset 500; vnd.api+json / text-json / 0 B → 400 |
| 16:32:31–38 | g5_1–4: 429, retry-after 212/210/208/205 → 16:35:43/44 + ct5b 400 |
| 16:38:00–07 | fin0–4: 401 (final credential probes) |
| 16:39:12 | closeout: uptime 826992; beacon 500; stats 200 — regression active |
| 16:42:16–17 | fp1–3: 405 nginx/1.31.5; fp4: 404 Express |

## Appendix E — Evidence index

Raw captures on disk in this workspace. Naming: `*_h` = response headers, `*_b` = response body; files in the workspace root = session 2 (15:43–16:42 UTC); `work/recon/` = session 1 (02:03–15:32); `*_verbose` = `curl -v` dumps. All times UTC Oct 5.

| Group | Location | Contents |
|---|---|---|
| recon | `work/recon/*` | session 1 (02:03–15:32): `admin_traffic_headers.txt`/`admin_traffic.html` (02:03:13), `js_headers.txt` (12:35:49), `o1`/`o2` `_b/_h`, `last_body`, `l(1)–l(8)` `_b/_h` (CF-405 side-entries in `l(2)_h`/`l(4)_h`/`l(8)_h`), `v1`/`r1`/`re1–re4` `_b/_h` (+`_verbose`), `av_b`/`av_h`/`avb`, `mb`, `gch`, `l2b`, `l3b`, `lb`, `tb`, `fb`, `http80`/`h80a`/`h80b`, `big.mp3` (9,437,189 B), `ub`/`ubh`, `d1b–d4b`, `cb`/`cb3`/`cb4`, `opt`, `cz`, `css_current.css`, `js_current.js` (492,467 B), `js_stale.js`, `robots.txt` (502 B = SPA), `home.html`, `js_admin.html`, `js_home2.html`, `gb`, `index-BxDtU8ue.js` (502 B = SPA) |
| regression (M-1) | root + `work/` | `t1–t7` `_b/_h`, `m1–m16_b` (m3 not saved), `a1–a12_b`, `b1–b7_b` (incl. `b3_1`/`b3_2`), `c1–c7_b`, `d1–d7_b`, `e1–e5_b`, `f1–f4_b`, `g1_b` + `work/verify1.txt`, `work/verify2.txt`, `work/beacon_h.txt`, `work/day2.txt`, `work/day2b.txt`, `work/getbody.txt`, `work/ua_matrix.txt`, `work/probe3.txt`, `work/probe4.txt`, `work/probe5.txt` |
| rate-limit (L-2) | root + `work/` | `g2_1–4_b`, `g3_1–4_b`, `g4_1–4_b/_h`, `g5_1–4_b/_h`, `s2_1–s2_12_b`, `s2_6_h`, `s2_8_h` (root); `rateprobe_b/_h`, `rateprobe2_b/_h` (work/) + `work/guess1–5.ps1/.txt`, `work/sweep2.ps1/.txt` |
| body/CT matrices | root + `work/` | `sh1–sh6_b`, `pw1–pw9_b`, `mp1_b`/`mp_body.bin`, `ct_ct1–ct_ct6_b` (ct5 slot via `ct5b_b`) + `work/shapecheck.txt`, `work/ctcheck.txt`, `work/pagewhite.txt` |
| closeout | root + `work/` | `fin0–fin4_b/_h`, `co1–co3_b`, `fp1–fp4_b/_h` + `work/final.txt`, `work/fingerprint.ps1/.txt`, `work/closeout.txt` |
| scripts | `work/*.ps1` | all probe scripts: `login1–3`, `origin1–3`, `mut1/2`, `rl1`, `up1–3`, `verify1/2`, `guess1–5`, `sweep2`, `ua_matrix`, `final`, `fingerprint`, `closeout`, `analyze*`, `probe1–5`, `l2/3`, `enum1`, `fuzz1`, `avtest`, `beacon`, `dbg`, `dump_cwd`, `enc_check`, `extract_ts`, `timeline_index`, … |

Concatenated recon indices: `work/recon_dump.txt`, `work/recon_key.txt`, `work/recon_key2.txt`.

## Appendix F — Scope & limitations

- **No valid credentials.** ≈79 login requests (Appendix B) across `baihu`/`admin`/`fox`/`root`/`test` + probe users and 15+ passwords; every one failed. §5 items (stored XSS, `backgroundUrl` fetch, upload validation, IDOR, cookie flags, admin-only surface) are identified from the production JS bundle and remain **unverified**.
- **Single vantage IP.** All traffic from one client (CF pops TPE/HKG/NRT/SEA/KIX seen in `CF-RAY`); per-IP vs global limiter scope is therefore inconclusive (L-2, Appendix C.3).
- **Login volume by design.** The 401/429/500 mix in Appendix B is deliberate limiter characterization, not a brute-force; no attack was run against any successful-auth path.
- **Not covered:** subdomains, availability/DoS, HTTP/2 protocol layer, TLS cipher-suite audit, authenticated-session testing, business-logic tests on admin data.
- **Client side:** JS bundle analysis is static (client logic only); no instrumentation of the running SPA.
- **Cloudflare-front inconsistencies.** Some methods (e.g. `TRACE`) are answered at the CF edge; others reach origin nginx/Express (Appendix A.3). Header attribution is per-layer, not one consistent surface.
- **M-1 onset bounded, not pinpointed.** Last healthy beacon 13:40:24; first observed 500 15:46:48. The process ran continuously from 2026-09-26 02:56:00 (Appendix D), so the change was a config/data/hot-reload/CF-layer change, not a deploy or restart; no server logs were available to identify it.
- **Timestamps.** `Date:` headers ±0 s; file mtimes ±1–2 s (stored with Taipei local time, UTC+8: Oct 5 下午 11:46 = 15:46 UTC; Oct 6 上午 12:39 = 16:39 UTC). All times in this report are UTC Oct 5 unless stated.
- **Status at report time.** Report dated 2026-10-06; the M-1 regression was still active at the last checks (16:39:12 beacon 500; 16:42:17 fingerprint probes) and was not re-checked after the session.
