# Security Audit Report — time.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://time.com/ |
| Bug bounty program | TIME |
| Listed scope domain | time.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 3 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H2c | HSTS not preloaded | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |

## Detailed findings

### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://time.com/; no defense-in-depth against XSS/content injection.

### 2. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://time.com/; page may be rendered in a foreign frame.

### 3. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-12T16:26:59+00:00 (17 days left) for time.com.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for time.com lists 1 name(s) besides the scope host: *.time.com

### 5. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://time.com/; full URL (incl. query strings) is sent as referrer by default.

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://time.com/; browser features (camera, mic, geolocation) unrestricted.

### 8. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://time.com/ lists 3175 URLs.

### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://time.com/ -> https://time.com/ (positive check).

### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://time.com/ exposes 79 unique Disallow path(s) (*/munich/index_html*, /*?*/*ref, /*?*002/*0902, /*?*2&hubs_content, /*?*PageSpeed) and 9 sitemap reference(s)

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://time.com/ final status: 200 (final URL https://time.com/).
- http://time.com/ initial status: 301.
- Certificate: Certainly Certainly Intermediate R1, valid until 2026-10-12T16:26:59+00:00.

## Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before the latest passive re-audit was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 10 findings: 0 high, 0 medium, 3 low, 7 info</summary>

### Security Audit Report — time.com

#### Scope and authorization

| Item | Value |
|---|---|
| Target | https://time.com/ |
| Bug bounty program | TIME |
| Listed scope domain | time.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

#### Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 2 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 3 | low | T3 | TLS certificate expiring within 30 days | CWE-298 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | H2c | HSTS not preloaded | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 9 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 10 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |

#### Detailed findings

##### 1. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://time.com/; no defense-in-depth against XSS/content injection.

##### 2. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://time.com/; page may be rendered in a foreign frame.

##### 3. [LOW] TLS certificate expiring within 30 days (`T3`)

- **CWE:** CWE-298
- **Detail:** Certificate expires 2026-10-12T16:26:59+00:00 (17 days left) for time.com.

##### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for time.com lists 1 name(s) besides the scope host: *.time.com

##### 5. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

##### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://time.com/; full URL (incl. query strings) is sent as referrer by default.

##### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://time.com/; browser features (camera, mic, geolocation) unrestricted.

##### 8. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://time.com/ lists 3175 URLs.

##### 9. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://time.com/ -> https://time.com/ (positive check).

##### 10. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://time.com/ exposes 79 unique Disallow path(s) (*/munich/index_html*, /*?*/*ref, /*?*002/*0902, /*?*2&hubs_content, /*?*PageSpeed) and 9 sitemap reference(s)

#### Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://time.com/ final status: 200 (final URL https://time.com/).
- http://time.com/ initial status: 301.
- Certificate: Certainly Certainly Intermediate R1, valid until 2026-10-12T16:26:59+00:00.

#### Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before PR #1 was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 15 findings: 0 high, 1 medium, 7 low, 7 info</summary>

##### Security Audit Report - time.com

> **Consolidated report** - union of two independent passes on the same target: random bounty hunt phase 24 (agent-random, 2026-09-25) and aggressive injection hunt wave-6 (agent-aggressive, 2026-09-24/25). Findings below are the deduplicated union (matched by ID + finding name); per-pass provenance is in the reproduction notes.


###### Scope and authorization

| Item | Value |
|---|---|
| Target | https://time.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | time.com |
| Test date | 2026-09-25 00:40 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

###### Summary

Total findings: **15** (High: 0, Medium: 1, Low: 7, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 9 | info | A10b | Sitemap enumerates URLs | CWE-200 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | H7 | X-Powered-By disclosure | CWE-200 |
| 14 | info | P3 | Missing security.txt | CWE-1038 |
| 15 | info | T2 | TLS certificate expiring within 18 days | CWE-295 |

###### Detailed findings

##### 1. [MEDIUM] mail.time.com - CloudFront distribution + edge function, 404 default on all paths (`S1`)

- **CWE:** CWE-916
- **Detail:** mail.time.com -> 3.169.55.64 (CloudFront 8ad72c38f68920ee5b40a6b6070b6b0). RETEST 2026-09-25: an edge CloudFront function (x-cache: LambdaGeneratedResponse) 301-redirects every path to a trailing-slash variant (/actuator -> /actuator/, /x -> /x/); the slash variants return the CloudFront DEFAULT 404 page (8475B, NOINDEX/NO-CACHE). Distribution is active but the origin serves nothing = dangling-content takeover candidate (claim the origin bucket/distribution). KEPT as medium.

##### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

##### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

##### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

##### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

##### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

##### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

##### 8. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Host header alters response (vhost behavior)
- **Recommendation:** Review and remediate per CWE guidance.

##### 9. [INFO] Sitemap enumerates URLs (`A10b`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml lists 5602 URLs; sensitive-looking entries: none.
- **Recommendation:** Remove or protect internal/sensitive URLs from the public sitemap.

##### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

##### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

##### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Varnish
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

##### 13. [INFO] X-Powered-By disclosure (`H7`)

- **CWE:** CWE-200
- **Detail:** X-Powered-By: Next.js
- **Recommendation:** Remove the X-Powered-By header.

##### 14. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

##### 15. [INFO] TLS certificate expiring within 18 days (`T2`)

- **CWE:** CWE-295
- **Detail:** TLS certificate expiring within 18 days
- **Recommendation:** Review and remediate per CWE guidance.

###### Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- robots_disallow: ["/?search*","/*?pano=*","*/munich/index_html*","/*?__rmid___get___page","/*?*__hsfp","/*?*__hstc","/*?*__rmid","/*?*__rmidpage","/*?*/*ref","/*?*002/*0902","/*?*2&hubs_content","/*?*ajs_event","/*?*app","/*?*attachment_id","/*?*author","/*?*bcpid","/*?*bcpidpage","/*?*cat","/*?*controlsVisibleOnLoad","/*?*country"]
- sitemap: {"total":5602,"sensitive":[]}

Stage-2 probe log (observed responses):
- timing base=563ms id=268 search=139
- boolean b=200/1319985 t1=406/0 t2=200/1320017
- graphql /graphql -> 301
- graphql /api/graphql -> 301
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 301
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406
- trav2 /%2e%2e%00.html -> 406
- trav2 /static//../../../../../../etc/passwd -> 301
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 301
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 406
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 406
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 406
- apicors /api -> 301
- apicors /api/v1 -> 301
- apicors /graphql -> 301
- apicors /rest -> 301
- apicors /v1 -> 301

**Stage 3 - live parameter harvest, takeover and injection probes (43 requests):**

- params_harvested: ["render","id","branch","source","hl"]

Stage-3 probe log (observed responses):
- harvest discovered 5 live query params
- xss3 https://www.google.com/recaptcha/enterprise.js?render -> err
- xss3 https://www.googletagmanager.com/gtm.js?id -> err
- xss3 https://static.time.com/v3/assets/bltea6093859af6183b/blt15191143a1927dff/6ab190c8bbb02aa678181934/admiral-paparo-time-2026-03.jpg?branch -> err
- xss3 /newsletters/?source -> 406
- xss3 https://www.instagram.com/time/?hl -> err
- subs no dangling service CNAMEs over 16 subdomains

###### Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://time.com/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "TIME | Current &amp; Breaking News | National &amp; World Updates",
  "path_gitconfig": 301,
  "path_envfile": 404,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 301",
    "sqli /?id=1%27+OR+1=1-- -> 406",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 301",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 301",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 406",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 406",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 406",
    "trav /static/../../../../../../../../etc/passwd -> 301",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 301",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 406",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 301",
    "host no reflection -> 421",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=563ms id=268 search=139",
    "boolean b=200/1319985 t1=406/0 t2=200/1320017",
    "graphql /graphql -> 301",
    "graphql /api/graphql -> 301",
    "sweep no hits over 26 paths",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 301",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406",
    "trav2 /%2e%2e%00.html -> 406",
    "trav2 /static//../../../../../../etc/passwd -> 301",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 301",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 406",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 406",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 406",
    "redir2 no hits over 49 requests",
    "apicors /api -> 301",
    "apicors /api/v1 -> 301",
    "apicors /graphql -> 301",
    "apicors /rest -> 301",
    "apicors /v1 -> 301"
  ],
  "robots_disallow": [
    "/?search*",
    "/*?pano=*",
    "*/munich/index_html*",
    "/*?__rmid___get___page",
    "/*?*__hsfp",
    "/*?*__hstc",
    "/*?*__rmid",
    "/*?*__rmidpage",
    "/*?*/*ref",
    "/*?*002/*0902",
    "/*?*2&hubs_content",
    "/*?*ajs_event",
    "/*?*app",
    "/*?*attachment_id",
    "/*?*author",
    "/*?*bcpid",
    "/*?*bcpidpage",
    "/*?*cat",
    "/*?*controlsVisibleOnLoad",
    "/*?*country"
  ],
  "sitemap": {
    "total": 5602,
    "sensitive": []
  },
  "v3_probe_count": 43,
  "v3_log": [
    "harvest discovered 5 live query params",
    "xss3 https://www.google.com/recaptcha/enterprise.js?render -> err",
    "xss3 https://www.googletagmanager.com/gtm.js?id -> err",
    "xss3 https://static.time.com/v3/assets/bltea6093859af6183b/blt15191143a1927dff/6ab190c8bbb02aa678181934/admiral-paparo-time-2026-03.jpg?branch -> err",
    "xss3 /newsletters/?source -> 406",
    "xss3 https://www.instagram.com/time/?hl -> err",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ],
  "params_harvested": [
    "render",
    "id",
    "branch",
    "source",
    "hl"
  ],
  "source": " + merged aggressive-injection-hunt pass (agent-aggressive, wave-6, 2026-09-25)"
}
```

###### Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.

</details>

</details>
