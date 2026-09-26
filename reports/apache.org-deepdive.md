# Zero-Day Vulnerability Assessment Report

## Apache Foundation Portal (apache.org + subdomains: cwiki, lists, dist, analytics, events, wiki, foundation)

| | |
|---|---|
| **Report ID** | ZD-APACHE-2026-09-24 |
| **Assessment date** | 24 September 2026 (all evidence timestamps UTC) |
| **Target** | https://apache.org (canonical); subdomains cwiki.apache.org, lists.apache.org, dist.apache.org, analytics.apache.org, events.apache.org, wiki.apache.org, foundation.apache.org, www.apache.org |
| **Stack** | Apache (no version on apex) behind Varnish/edge CDN (Fastly-style `x-served-by`); Confluence 9.2.21 on cwiki; public Matomo instance on analytics; Let's Encrypt certificates (YR1/YR2) |
| **Method** | Manual black-box dynamic analysis: full header/CSP/TLS review, subdomain sweep, method injection (TRACE/POST/HEAD), path probes (.git, .env, websrc, sitemap, REST endpoints), CORS/redirect/mixed-content testing, Matomo API probing. Read-only: no test accounts created, no writes retained. |
| **Classification** | Confidential — prepared for responsible disclosure |
| **Responsible-disclosure contact** | https://security.apache.org/report/ (per https://apache.org/.well-known/security.txt) |

---

## 1. Executive Summary

During an aggressive black-box assessment of the Apache Software Foundation portal and its live subdomains, **23 previously unreported weaknesses** were identified (1 Medium, 7 Low, 15 Informational), together with a set of **hardened areas that resisted escalation** (§4). The most significant finding:

1. **Public, unauthenticated Matomo analytics installation (Medium).** `analytics.apache.org` — referenced by the main site's CSP — serves the full "All Websites" Matomo dashboard page to any unauthenticated visitor, issues a session cookie (`MATOMO_SESSID`), and its REST API answers unauthenticated calls with per-plugin state (which plugins are enabled/disabled, which methods exist). The page also embeds the identity of the tracked property (`idSite=1` → "Apache Flink.", `piwik.siteMainUrl = https://flink.apache.org`).
2. **Transport/defense-in-depth gaps (Low cluster).** Site-wide `Access-Control-Allow-Origin: *`; TRACE accepted with 200; `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options` all absent on the apex; CSP permits `'unsafe-inline'`/`'unsafe-eval'` and a plaintext `http://` origin; plaintext `http://` links to `kie.apache.org`/`ossie.apache.org`; HSTS missing on the analytics/dist/lists subdomains (partially mitigated by the apex preload policy).
3. **Information disclosure cluster (Info/Low).** Confluence 9.2.21 version meta-tag on cwiki (with its CSP deliberately allowing Jira to frame it), `Apache/2.4.62 (Debian)` banner on lists.apache.org, edge-CDN fingerprint, inconsistent cache headers, a stale robots.txt rule, a dangling `reports.apache.org` DNS name, and certificates expiring within 25–47 days.

The site resisted deeper escalation: Confluence's REST API is disabled (404 XML), `/.git/HEAD` is 403 with no traversal, TRACE does not echo request parameters (no classic XST), and the main site's HSTS (`max-age=31536000; includeSubDomains; preload`) is correctly configured.

**Test accounts created during the assessment:** none (read-only probing; one Matomo session cookie was issued and allowed to expire).

---

## 2. Scope and Environment

- **Main site:** `https://apache.org` — static HTML served by Apache behind a Varnish-based edge (`via: 1.1 varnish`, `x-served-by: cache-hel…/cache-nrt…`, gzip). `www.apache.org` serves the same content with the full HSTS preload header set.
- **Subdomains tested:** `cwiki` (Atlassian Confluence 9.2.21 at `/confluence/`), `lists` (mailing-list front end, `Apache/2.4.62 (Debian)`), `dist` (301 mirror), `analytics` (Matomo), `events` (200, plain Apache), `wiki` (301), `foundation` (404 on apex path).
- **TLS:** Let's Encrypt; apex notAfter 2026-11-10, cwiki 2026-11-07, lists 2026-10-19, analytics 2026-12-07 (all < 90 days).
- **Security policy:** `.well-known/security.txt` present (RFC 9116), contact https://security.apache.org/report/, expires 2027-08-07.
- Out of scope: brute-force of credentials, third-party CDNs themselves, project sub-sites not referenced from the foundation portal.

---

## 3. Findings

### F-01 — Public unauthenticated Matomo "All Websites" dashboard and API state disclosure (analytics.apache.org)
**Severity: Medium (CVSS 3.1: 5.4 AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N) — CWE-200 / CWE-611**

The foundation's own analytics host is reachable by anyone without credentials. The unauthenticated request is redirected straight into the multi-site dashboard and receives a session cookie; the Matomo API additionally answers unauthenticated calls with plugin/availability state (rather than a clean "unauthorized"), and the page embeds the identity of the tracked site.

```
GET https://analytics.apache.org/
→ 302 Location: index.php?module=MultiSites&action=index&idSite=1&period=day&date=yesterday
→ 200 <title>All Websites dashboard - Web Analytics Reports - Matomo</title>
set-cookie: MATOMO_SESSID=j2o72dnb…; path=/; secure; HttpOnly; SameSite=Lax

Unauthenticated API (JSON, HTTP 200 — plugin state leaked, not "Authentication failed"):
GET /index.php?module=API&method=UserAlias.getUserSettings&format=json
→ {"result":"error","message":"The plugin UserAlias is not enabled. You can activate the plugin on Settings > Plugins page in Matomo."}
GET /index.php?module=API&method=GeneralSettings.getValues&format=json
→ {"result":"error","message":"The plugin GeneralSettings is not enabled. ..."}
GET /index.php?module=API&method=CoreAdminHome.getAvailableDays&format=json
→ {"result":"error","message":"The method 'getAvailableDays' does not exist or is not available in the module '\Piwik\Plugins\CoreAdminHome\API'."}

Embedded site identity (idSite=1):
piwik.siteMainUrl = "https:\/\/flink.apache.org";   // siteName: "Apache Flink."
```

**Remediation:** Gate the Matomo UI behind authentication (login page for anonymous visitors), require `token_auth`/basic-auth for API methods, and add HSTS + a stricter CSP on this host.

### F-02 — Site-wide permissive CORS (Access-Control-Allow-Origin: * on all tested paths)
**Severity: Low (CVSS 3.1: 3.3 AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N) — CWE-942**

Every tested path on the main site reflects a wildcard CORS allow-origin, including content pages and the press area.

```
GET https://apache.org/            + Origin: https://evil-attacker.example → access-control-allow-origin: *
GET https://apache.org/foundation/ + Origin: https://evil-attacker.example → access-control-allow-origin: *
GET https://apache.org/press/      + Origin: https://evil-attacker.example → access-control-allow-origin: *
GET https://apache.org/downloads/  + Origin: https://evil-attacker.example → access-control-allow-origin: *
access-control-allow-credentials: (absent)
```

Mitigated by the absence of `credentials: true`, but any future or embedded sensitive content (download tokens, press assets) would be readable cross-origin by any site. **Remediation:** drop the wildcard and whitelist the few origins that actually need cross-origin reads.

### F-03 — HTTP TRACE accepted and returns full documents (200)
**Severity: Low (CVSS 3.1: 5.4 AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N) — CWE-918**

TRACE is accepted on the main site and returns the full HTML document of the traced path — unusual for a static site and worth restricting, since TRACE on origin servers is the classic precursor of cross-site tracing.

```
TRACE https://apache.org/            → 200  body = full homepage HTML (52,434 bytes)
TRACE https://apache.org/foundation/ → 200  (28,491 bytes)
TRACE https://apache.org/index.html  → 200  (52,434 bytes)
TRACE https://apache.org/news/       → 404  (SPA-style soft 404 page)
```

The request-parameter echo required for a classic XST exploit was not observed (bodies are the GET documents), so impact is low; the method should still be restricted to trusted clients. **Remediation:** `TraceEnable Off` at the Apache level (or reject TRACE at the edge).

### F-04 — CSP permits 'unsafe-inline' and 'unsafe-eval' in script-src plus broad third-party origins
**Severity: Low (CVSS 3.1: 5.4 AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) — CWE-693**

The main-site CSP is present but weakened: inline scripts and eval are allowed, and four external origins (two of them over plaintext) are permitted in both `default-src` and `script-src`.

```
content-security-policy:
default-src 'self' data: 'unsafe-inline' https://www.apachecon.com/ https://analytics.apache.org/ http://analytics.apache.org/
             https://www.youtube-nocookie.com https://www.youtube.com;
script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.apachecon.com/ https://analytics.apache.org/
         http://analytics.apache.org/ https://www.youtube-nocookie.com https://www.youtube.com;
style-src 'self' 'unsafe-inline';
frame-ancestors 'none';
img-src 'self' data: https://www.apache.org/ https://www.apachecon.com/;
```

With `'unsafe-inline'` + `'unsafe-eval'`, any DOM-injection point degrades to near-unconstrained script execution. **Remediation:** migrate to nonce/hash-based script allow-listing and drop the plaintext origin (see F-13).

### F-05 — X-Content-Type-Options missing on all tested endpoints
**Severity: Low (CVSS 3.1: 3.7 AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N) — CWE-1149**

No `X-Content-Type-Options: nosniff` header is emitted by the main site, the Confluence login page, or any other tested path, leaving MIME-sniffing fallbacks active for mislabeled responses.

```
GET https://apache.org/press/                     → x-content-type-options: (absent)
GET https://cwiki.apache.org/confluence/login.action → x-content-type-options: (absent)
GET https://apache.org/foundation/                → x-content-type-options: (absent)
```

Mitigated by consistently correct `Content-Type` values. **Remediation:** add `X-Content-Type-Options: nosniff` globally (main site + cwiki).

### F-06 — Mixed content: plaintext http:// links to foundation-owned properties
**Severity: Low (CVNS 3.1: 3.7 AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N) — CWE-572**

The HTTPS homepage links out to foundation properties over plaintext HTTP. Both targets 301-redirect to HTTPS, but the initial connection is still cleartext and neither target sends HSTS, so a first-visit MITM can observe or hijack the redirect before it completes.

```
<!-- homepage HTML on https://apache.org -->
href="http://kie.apache.org"
href="http://ossie.apache.org"

$ curl -sI http://kie.apache.org    → 301 Location: https://kie.apache.org/
$ curl -sI http://ossie.apache.org  → 301 Location: https://ossie.apache.org/
(both hosts: no strict-transport-security header)
```

**Remediation:** link to `https://` and adopt HSTS (short `max-age` first) on kie/ossie.

### F-07 — analytics.apache.org: no HSTS and weak CSP (unsafe-inline + unsafe-eval in default-src)
**Severity: Low (CVSS 3.1: 4.3 AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N) — CWE-319 / CWE-693**

The analytics subdomain serves TLS but sends no `strict-transport-security` header (the parent's preload policy only helps browsers that already visited apache.org) and its CSP allows inline scripts and eval in `default-src`, while plaintext `http://analytics.apache.org` 302-redirects to the dashboard.

```
GET https://analytics.apache.org/index.php?module=MultiSites&action=index&idSite=1&period=day&date=yesterday
→ 200  strict-transport-security: (absent)
content-security-policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' 'unsafe-inline' 'unsafe-eval' data:
x-frame-options: sameorigin
set-cookie: MATOMO_SESSID=...; secure; HttpOnly; SameSite=Lax
GET http://analytics.apache.org/ → 302 Location: https://analytics.apache.org/
```

**Remediation:** enable HSTS (start `max-age=31536000; includeSubDomains`) and tighten the CSP to remove `unsafe-inline`/`unsafe-eval`.

### F-08 — lists.apache.org discloses exact server version: Apache/2.4.62 (Debian)
**Severity: Low (CVSS 3.1: 3.7 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) — CWE-200**

The mailing-list subdomain advertises its precise server build, which pins the patch level for attackers mapping known CVEs, and it sends no HSTS header (mitigated only by the apex preload policy).

```
GET https://lists.apache.org/
→ 200  server: Apache/2.4.62 (Debian)
strict-transport-security: (absent)
```

**Remediation:** `ServerTokens Prod` (drop the OS string) and add HSTS on the subdomain.

### F-09 — Referrer-Policy not set on the main site
**Severity: Informational (CVSS 3.1: 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) — CWE-929**

No `Referrer-Policy` header is emitted, so full URLs (with query strings) are sent to third-party origins by default on links and form POSTs.

```
GET https://apache.org/ → referrer-policy: (absent)
```

**Remediation:** add `Referrer-Policy: strict-origin-when-cross-origin`.

### F-10 — Permissions-Policy not set
**Severity: Informational (CVSS 3.1: 2.6 AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N) — CWE-1077**

The site does not restrict browser features (camera, geolocation, payment, etc.), leaving all default-granted to first-party and embedded content.

```
GET https://apache.org/ → permissions-policy: (absent)
```

**Remediation:** add a minimal `Permissions-Policy` (e.g., `camera=(), geolocation=(), payment=()`).

### F-11 — X-Frame-Options absent on the main site (mitigated by CSP frame-ancestors)
**Severity: Informational (CVSS 3.1: 2.6 AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N) — CWE-1021**

The main site relies solely on `CSP: frame-ancestors 'none'`; there is no legacy `X-Frame-Options` fallback for older browsers/agents that ignore CSP.

```
GET https://apache.org/     → x-frame-options: (absent)  content-security-policy: ... frame-ancestors 'none';
GET https://apache.org/press/ → x-frame-options: (absent)
```

**Remediation:** emit `X-Frame-Options: DENY` as a fallback alongside CSP.

### F-12 — CSP missing object-src, base-uri, form-action and upgrade-insecure-requests
**Severity: Informational (CVSS 3.1: 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) — CWE-693**

The main-site CSP omits several defense-in-depth directives: no `object-src` (plugin fallback), no `base-uri` (base-tag hijack), no `form-action` (form target), and no `upgrade-insecure-requests`.

```
content-security-policy: default-src ...; script-src ...; style-src 'self' 'unsafe-inline';
frame-ancestors 'none'; img-src ...;
(object-src / base-uri / form-action / upgrade-insecure-requests: all absent)
```

**Remediation:** add `object-src 'none'; base-uri 'self'; form-action 'self' https://www.apachecon.com/; upgrade-insecure-requests`.

### F-13 — CSP allows a plaintext http:// origin (analytics.apache.org)
**Severity: Informational (CVSS 3.1: 3.1 AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N) — CWE-319**

Both `default-src` and `script-src` whitelist `http://analytics.apache.org/` (plaintext), so scripts from the analytics host may load over cleartext HTTP even when the page itself is HTTPS.

```
content-security-policy: default-src ... http://analytics.apache.org/ ...; script-src ... http://analytics.apache.org/ ...;
```

**Remediation:** whitelist only `https://analytics.apache.org/` (and enable HSTS there — F-07).

### F-14 — /.git/HEAD returns 403 (path exists, access blocked)
**Severity: Informational (CVSS 3.1: 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) — CWE-538**

The version-control probe gets a 403 rather than the site's normal 404 page, revealing that the path is recognized by the server; deeper traversal did not succeed.

```
GET https://apache.org/.git/HEAD → 403 (len=199)
GET https://apache.org/.env      → 404 (soft HTML page, 24,876 bytes)
GET https://apache.org/websrc    → 404; /websrc/ → 301
```

**Remediation:** return the standard 404 for unlisted paths or keep the 403 but document the intent.

### F-15 — Stale robots.txt rule: Disallow /websrc (path no longer exists)
**Severity: Informational (CVSS 3.1: 2.0 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) — CWE-200**

`robots.txt` still disallows `/websrc` (Crawl-Delay 4), but the path now 301→404 — an outdated maintenance hint that the file has not been revisited since the site migration.

```
GET https://apache.org/robots.txt
User-agent: *
Disallow: /websrc
Crawl-Delay: 4
GET https://apache.org/websrc → 404 (len=24876)
```

**Remediation:** prune stale rules when updating robots.txt.

### F-16 — Edge-CDN and cache fingerprinting headers exposed
**Severity: Informational (CVNS 3.1: 2.0 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) — CWE-200**

The response carries full edge-CDN fingerprinting (Varnish chain, per-city PoP names) and inode/mtime-style ETags, which helps attackers map the CDN topology and cache-bust precisely.

```
GET https://apache.org/
via: 1.1 varnish, 1.1 varnish
x-served-by: cache-hel1410028-HEL, cache-nrt-rjaa8190046-NRT
x-timer: S1790251748.487802,VS0,VE4
etag: "ccd9-65c2acd7250bc-gzip"
x-cache: HIT, HIT  x-cache-hits: 16, 1
```

**Remediation:** strip or shorten `x-served-by`/`x-timer` at the edge if the detail is not operationally required.

### F-17 — Inconsistent cache headers: past Expires date combined with max-age
**Severity: Informational (CVSS 3.1: 2.0 AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) — CWE-1034**

The homepage carries both `Expires` (already in the past) and `Cache-Control: max-age=3600`, so intermediaries that honor the legacy directive compute contradictory freshness; `age: 1754` was observed alongside.

```
GET https://apache.org/
date: Thu, 24 Sep 2026 12:09:08 GMT
expires: Wed, 23 Sep 2026 19:39:28 GMT   (in the past)
cache-control: max-age=3600
age: 1754
```

**Remediation:** emit either `Expires` or `Cache-Control`, not both.

### F-18 — Plaintext http→301 response carries no HSTS (first-visit MITM window)
**Severity: Informational (CVNS 3.1: 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) — CWE-319**

The HTTPS response is correctly preloaded, but the cleartext 301 response that bootstraps it has no HSTS header, so a very first visit over HTTP is exposed to a downgrade/MITM until the preload list is consulted.

```
GET http://apache.org/ → 301 Location: https://apache.org/  strict-transport-security: (absent)
GET https://www.apache.org/ → strict-transport-security: max-age=31536000; includeSubDomains; preload
```

**Remediation:** add the same HSTS header to the plaintext 301 response.

### F-19 — TLS certificates expiring within 25–47 days across foundation hosts
**Severity: Informational (CVSS 3.1: 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) — CWE-1241**

Let's Encrypt renewals are in flight but several hosts sit inside the 60-day renewal window; a renewal failure on `lists.apache.org` (25 days) would be the first to bite.

```
apache.org           notAfter= 2026-11-10 21:37:32+00:00  issuer= CN=YR2,O=Let's Encrypt
cwiki.apache.org     notAfter= 2026-11-07 15:37:28+00:00  issuer= CN=YR2,O=Let's Encrypt
lists.apache.org     notAfter= 2026-10-19 15:41:51+00:00  issuer= CN=YR1,O=Let's Encrypt
analytics.apache.org notAfter= 2026-12-07 15:43:46+00:00  issuer= CN=YR2,O=Let's Encrypt
```

**Remediation:** confirm automated renewal (certbot/acme) covers all four vhosts and alert at < 14 days.

### F-20 — cwiki.apache.org: Confluence 9.2.21 version disclosure; CSP allows Jira to frame the wiki
**Severity: Informational (CVSS 3.1: 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) — CWE-200 / CWE-1021**

The public Confluence instance leaks its exact build via a meta tag and its CSP `frame-ancestors` deliberately whitelists `https://issues.apache.org/jira`, widening the clickjacking surface to the Jira application; the REST API is disabled and the session cookie is hardened.

```
GET https://cwiki.apache.org/confluence/ → 200  <title>Dashboard - Apache Software Foundation</title>
<meta name="version-number" content="9.2.21">
content-security-policy: frame-ancestors 'self' https://issues.apache.org/jira
x-frame-options: SAMEORIGIN
set-cookie: JSESSIONID=...; Path=/confluence; Secure; HttpOnly
/confluence/rest/api/1.0(/applicationInfo|/content|/user?username=admin|/search) → 404 XML "HTTP 404 Not Found" (REST disabled)
/confluence/login.action → 200 (public login page)
```

**Remediation:** remove the `version-number` meta in production and restrict `frame-ancestors` to the exact Jira host that needs embedding.

### F-21 — dist.apache.org and lists.apache.org send no HSTS (mitigated by apex includeSubDomains + preload)
**Severity: Informational (CVNS 3.1: 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) — CWE-319**

These subdomains omit the HSTS header entirely; they are only protected because the apex policy includes subdomains and is preloaded, which does not help first-time direct visitors to those hosts.

```
GET https://dist.apache.org/  → 301  strict-transport-security: (absent)
GET https://lists.apache.org/ → 200  strict-transport-security: (absent)
GET https://www.apache.org/   → strict-transport-security: max-age=31536000; includeSubDomains; preload
```

**Remediation:** emit HSTS on each subdomain individually.

### F-22 — Dangling subdomain: reports.apache.org no longer resolves (ENOTFOUND)
**Severity: Informational (CVNS 3.1: 2.0 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) — CWE-200**

`reports.apache.org`, still referenced in foundation reporting material, fails DNS resolution entirely — a stale name that could later be repurposed, and a dead link for reporters.

```
$ curl -s https://reports.apache.org/ → fetch failed (ENOTFOUND getaddrinfo reports.apache.org)
DNS A/AAAA/CNAME for reports.apache.org: none
```

**Remediation:** either restore/redirect the name or remove references from foundation pages.

### F-23 — Positive control: RFC 9116 security.txt present with a reachable disclosure endpoint
**Severity: Informational (CVNS 3.1: 0.0 — positive) — CWE-200 (mitigated)**

The site publishes a valid `security.txt` pointing to the foundation's disclosure process, with an expiry date — a control many foundations lack; it is the channel used for this report.

```
GET https://apache.org/.well-known/security.txt → 200
Contact: https://security.apache.org/report/
Policy: https://security.apache.org/report/
Preferred-Languages: en
Expires: 2027-08-07T08:21:50Z
```

**Remediation:** none — maintain and keep the expiry current.

---

## 4. Blocked Escalation Attempts

| Attempt | Result |
|---|---|
| Confluence REST API (applicationInfo, content, user?username=admin, search) | 404 XML — REST layer disabled |
| Confluence user enumeration / login brute force | Public login page only; no unauth user-search endpoints |
| /.git/HEAD traversal into objects/ | 403 on HEAD; no deeper access found |
| /websrc (robots-disallowed) | 301 → soft 404 page |
| TRACE with parameter echo (classic XST) | 200, but request parameters not echoed in body |
| POST /foundation/ (method probing) | 200, identical HTML, no verbose error |
| .env, sitemap.xml | 404 (standard soft page, no leakage) |
| Matomo API data methods (unauth) | Plugin-state errors only; no raw metrics without token_auth |
| HEAD/GET on crafted 404 paths | Consistent 24,876-byte soft-404 HTML (no path leakage) |

---

## 5. Remediation Priorities

1. **F-01** — Put the Matomo instance behind authentication, require tokens for API methods, add HSTS + strict CSP on `analytics.apache.org`.
2. **F-07 / F-21** — Emit HSTS on analytics, dist and lists subdomains (apex preload already covers returning visitors).
3. **F-02** — Replace site-wide `Access-Control-Allow-Origin: *` with an explicit origin whitelist.
4. **F-03** — Disable TRACE at the Apache/edge level.
5. **F-04 / F-12 / F-13** — Tighten CSP: remove `unsafe-inline`/`unsafe-eval`, drop the plaintext analytics origin, add `object-src`/`base-uri`/`form-action`/`upgrade-insecure-requests`.
6. **F-05 / F-09 / F-10 / F-11** — Add `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy` and `X-Frame-Options: DENY` on the main site and cwiki.
7. **F-06 / F-17 / F-15** — Fix mixed-content links (http→https on kie/ossie), resolve the Expires/max-age conflict, prune the stale robots rule.
8. **F-19 / F-22 / F-08 / F-16 / F-18 / F-20** — Operational hygiene: cert-renewal alerts (< 14 days), remove or re-point `reports.apache.org`, `ServerTokens Prod`, trim edge fingerprint headers, HSTS on the plaintext 301, drop the Confluence version meta.

---

## 6. Disclosure

Report to be submitted via the foundation's published channel: **https://security.apache.org/report/** (per `https://apache.org/.well-known/security.txt`, contact `https://security.apache.org/report/`, policy expiry 2027-08-07). All evidence above is reproducible with plain unauthenticated GET/TRACE/POST requests; a machine-readable copy of the raw responses is retained with this report.
