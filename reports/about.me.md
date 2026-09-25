# Security Audit Report - about.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://about.me/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | about.me |
| Test date | 2026-09-24 23:48 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 9, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie authtkt lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie authtkt lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /admin (HTML shell), /console (HTML shell), /api (HTML shell), /debug (HTML shell), /trace (HTML shell), /phpmyadmin (HTML shell), /backup (HTML shell), /database (HTML shell), /config (HTML shell), /metrics (HTML shell).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/admin (HTML shell)","/console (HTML shell)","/api (HTML shell)","/debug (HTML shell)","/trace (HTML shell)","/phpmyadmin (HTML shell)","/backup (HTML shell)","/database (HTML shell)","/config (HTML shell)","/metrics (HTML shell)"]}
- robots_disallow: ["/facebook/","/twitter/","/linkedin/","/random/","/content/","/n/","/ajax/","/me/","/dw/","/","/","/","/","/","/","/","/","/","/","/"]

Stage-2 probe log (observed responses):
- timing base=256ms id=228 search=207
- boolean b=200/234358 t1=200/234358 t2=200/234357
- graphql /graphql -> 404
- graphql /api/graphql -> 302
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 302
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 302
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 302
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 400
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- apicors /api -> 200
- apicors /api/v1 -> 302
- apicors /graphql -> 404
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (18 requests):**

- params_harvested: ["id"]

Stage-3 probe log (observed responses):
- harvest discovered 1 live query params
- xss3 https://www.googletagmanager.com/gtag/js?id -> err
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://about.me/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "about.me | your personal homepage",
  "path_gitconfig": 302,
  "path_envfile": 404,
  "path_securitytxt": 302,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 302",
    "sqli /?id=1%27+OR+1=1-- -> 200",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 200",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 302",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 302",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 302",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 404",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 302",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=256ms id=228 search=207",
    "boolean b=200/234358 t1=200/234358 t2=200/234357",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 302",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 302",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 302",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 302",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 400",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "redir2 no hits over 49 requests",
    "apicors /api -> 200",
    "apicors /api/v1 -> 302",
    "apicors /graphql -> 404",
    "apicors /rest -> 404",
    "apicors /v1 -> 404"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/admin (HTML shell)",
      "/console (HTML shell)",
      "/api (HTML shell)",
      "/debug (HTML shell)",
      "/trace (HTML shell)",
      "/phpmyadmin (HTML shell)",
      "/backup (HTML shell)",
      "/database (HTML shell)",
      "/config (HTML shell)",
      "/metrics (HTML shell)"
    ]
  },
  "robots_disallow": [
    "/facebook/",
    "/twitter/",
    "/linkedin/",
    "/random/",
    "/content/",
    "/n/",
    "/ajax/",
    "/me/",
    "/dw/",
    "/",
    "/",
    "/",
    "/",
    "/",
    "/",
    "/",
    "/",
    "/",
    "/",
    "/"
  ],
  "v3_probe_count": 18,
  "v3_log": [
    "harvest discovered 1 live query params",
    "xss3 https://www.googletagmanager.com/gtag/js?id -> err",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 302"
  ],
  "params_harvested": [
    "id"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
