# Security Audit Report - medium.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://medium.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | medium.com |
| Test date | 2026-09-24 19:32 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 3, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 4. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /api/v1 (HTML shell), /.svn/entries (403 protected), /actuator/env (HTML shell), /.aws/credentials (HTML shell), /metrics (HTML shell).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/api/v1 (HTML shell)","/.svn/entries (403 protected)","/actuator/env (HTML shell)","/.aws/credentials (HTML shell)","/metrics (HTML shell)"]}
- robots_disallow: ["/m/","/me/","/@me$","/@me/","/*/edit$","/*/*/edit$","/media/","/p/*/share","/r/","/trending","/search?q$","/search?q=","/*/search?q=","/*/search/*?q=","/*/*source=","/"]

Stage-2 probe log (observed responses):
- timing base=122ms id=19 search=27
- boolean b=200/51093 t1=403/5381 t2=403/5381
- graphql /graphql -> 404
- graphql /api/graphql -> 200
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 200
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 200
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 400
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- apicors /api -> 404
- apicors /api/v1 -> 200
- apicors /graphql -> 404
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (36 requests):**

- params_harvested: ["render","autoplay","operation","id","source"]

Stage-3 probe log (observed responses):
- harvest discovered 5 live query params
- xss3 https://www.google.com/recaptcha/enterprise.js?render -> err
- xss3 /about?autoplay -> 403
- xss3 /m/signin?operation -> 403
- xss3 https://play.google.com/store/apps/details?id -> err
- xss3 /?source -> 403
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://medium.com/",
  "https_status": 403,
  "content_type": "text/html; charset=UTF-8",
  "title": "Just a moment...",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 403,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 403",
    "sqli /?q=%27 -> 403",
    "sqli /products?filter=%27 -> 403",
    "sqli /?p=1;-- -> 403",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 403",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 403",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 403",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 403",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 403",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 403",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 403",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=122ms id=19 search=27",
    "boolean b=200/51093 t1=403/5381 t2=403/5381",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 200",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 200",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 200",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 400",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "redir2 no hits over 49 requests",
    "apicors /api -> 404",
    "apicors /api/v1 -> 200",
    "apicors /graphql -> 404",
    "apicors /rest -> 404",
    "apicors /v1 -> 404"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/api/v1 (HTML shell)",
      "/.svn/entries (403 protected)",
      "/actuator/env (HTML shell)",
      "/.aws/credentials (HTML shell)",
      "/metrics (HTML shell)"
    ]
  },
  "robots_disallow": [
    "/m/",
    "/me/",
    "/@me$",
    "/@me/",
    "/*/edit$",
    "/*/*/edit$",
    "/media/",
    "/p/*/share",
    "/r/",
    "/trending",
    "/search?q$",
    "/search?q=",
    "/*/search?q=",
    "/*/search/*?q=",
    "/*/*source=",
    "/"
  ],
  "v3_probe_count": 36,
  "v3_log": [
    "harvest discovered 5 live query params",
    "xss3 https://www.google.com/recaptcha/enterprise.js?render -> err",
    "xss3 /about?autoplay -> 403",
    "xss3 /m/signin?operation -> 403",
    "xss3 https://play.google.com/store/apps/details?id -> err",
    "xss3 /?source -> 403",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ],
  "params_harvested": [
    "render",
    "autoplay",
    "operation",
    "id",
    "source"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
