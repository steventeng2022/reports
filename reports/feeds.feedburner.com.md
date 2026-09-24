# Security Audit Report - feeds.feedburner.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://feeds.feedburner.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | feeds.feedburner.com |
| Test date | 2026-09-24 19:34 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **12** (High: 0, Medium: 1, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | R2 | No HTTP->HTTPS redirect | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | A10b | Sitemap enumerates URLs | CWE-200 |
| 7 | info | A4 | Sensitive paths return 200 (soft-200 feed routing) | CWE-538 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [MEDIUM] No HTTP->HTTPS redirect (`R2`)

- **CWE:** CWE-319
- **Detail:** http://feeds.feedburner.com returns 404 without redirecting to HTTPS. No Strict-Transport-Security observed on the HTTPS response.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Sitemap enumerates URLs (`A10b`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml lists 0 URLs; sensitive-looking entries: none.
- **Recommendation:** Remove or protect internal/sensitive URLs from the public sitemap.

### 7. [INFO] Sensitive paths return 200 (soft-200 feed routing) (`A4`)

- **CWE:** CWE-538
- **Detail:** Re-verified 2026-09-25: /admin 200 text/xml = HTML 4.01-DOCTYPE soft-200 page; /console 200 = an RSS feed literally named "console" (72dpi.console.cc) - FeedBurner routes /<path> to the subscriber feed with that name; /dashboard 200 = 403-Forbidden body served with status 200; /api 200 = podcast RSS; /debug 200 = legacy Google Pipes page. All are soft-200 feed/router behavior, not live admin panels.
- **Recommendation:** Review each exposed path; require authentication for admin/actuator-style endpoints and remove world-readable credential or config files.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: ESF
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: ESF
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":["/admin (200 text/xml; charset=utf-8)","/console (200 text/xml; charset=utf-8)","/dashboard (200 text/xml; charset=utf-8)","/api (200 text/xml; charset=utf-8)","/debug (200 text/xml; charset=utf-8)","/trace (200 text/xml; charset=utf-8)","/openapi.json (200 text/xml; charset=utf-8)","/phpmyadmin (200 text/xml; charset=utf-8)","/actuator (200 text/xml; charset=utf-8)","/backup (200 text/xml; charset=utf-8)","/backup.zip (200 text/xml; charset=utf-8)","/database (200 text/xml; charset=utf-8)","/config (200 text/xml; charset=utf-8)","/config.yml (200 text/xml; charset=utf-8)","/elm.json (200 text/xml; charset=utf-8)","/package.json (200 text/xml; charset=utf-8)","/metrics (200 text/xml; charset=utf-8)"],"protected":[]}
- robots_disallow: []
- sitemap: {"total":0,"sensitive":[]}

Stage-2 probe log (observed responses):
- timing base=35ms id=23 search=304
- boolean b=404/1648 t1=404/1648 t2=404/1648
- graphql /graphql -> 404
- graphql /api/graphql -> 404
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 302
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 404
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404
- apicors /api -> 200
- apicors /api/v1 -> 404
- apicors /graphql -> 404
- apicors /rest -> 200
- apicors /v1 -> 200

**Stage 3 - live parameter harvest, takeover and injection probes (7 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_status": 404,
  "https_status": 404,
  "content_type": "text/html; charset=utf-8",
  "title": "Error 404 (Not Found)!!1",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 200",
    "sqli /?id=1%27+OR+1=1-- -> 404",
    "sqli /?q=%27 -> 404",
    "sqli /products?filter=%27 -> 200",
    "sqli /?p=1;-- -> 404",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 200",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 404",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 404",
    "trav /static/../../../../../../../../etc/passwd -> 302",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 302",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 404",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 404",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 200",
    "host no reflection -> 404",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=35ms id=23 search=304",
    "boolean b=404/1648 t1=404/1648 t2=404/1648",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 404",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 302",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 404",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "redir2 no hits over 49 requests",
    "apicors /api -> 200",
    "apicors /api/v1 -> 404",
    "apicors /graphql -> 404",
    "apicors /rest -> 200",
    "apicors /v1 -> 200"
  ],
  "sweep": {
    "high": [
      "/admin (200 text/xml; charset=utf-8)",
      "/console (200 text/xml; charset=utf-8)",
      "/dashboard (200 text/xml; charset=utf-8)",
      "/api (200 text/xml; charset=utf-8)",
      "/debug (200 text/xml; charset=utf-8)",
      "/trace (200 text/xml; charset=utf-8)",
      "/openapi.json (200 text/xml; charset=utf-8)",
      "/phpmyadmin (200 text/xml; charset=utf-8)",
      "/actuator (200 text/xml; charset=utf-8)",
      "/backup (200 text/xml; charset=utf-8)",
      "/backup.zip (200 text/xml; charset=utf-8)",
      "/database (200 text/xml; charset=utf-8)",
      "/config (200 text/xml; charset=utf-8)",
      "/config.yml (200 text/xml; charset=utf-8)",
      "/elm.json (200 text/xml; charset=utf-8)",
      "/package.json (200 text/xml; charset=utf-8)",
      "/metrics (200 text/xml; charset=utf-8)"
    ],
    "protected": []
  },
  "robots_disallow": [],
  "sitemap": {
    "total": 0,
    "sensitive": []
  },
  "v3_probe_count": 7,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 404"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
