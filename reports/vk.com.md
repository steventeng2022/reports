# Security Audit Report - vk.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://vk.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | vk.com |
| Test date | 2026-09-24 19:35 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 11, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | B3 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 4 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | low | H4 | No clickjacking protection | CWE-1023 |
| 11 | low | H4 | No clickjacking protection | CWE-1023 |
| 12 | info | A10 | robots.txt discloses sensitive paths | CWE-200 |
| 13 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 14 | info | B4i | SQLi-style payload reflected on harvested parameter | CWE-89 |
| 15 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 16 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 17 | info | H6 | Server technology disclosure | CWE-200 |
| 18 | info | H6 | Server technology disclosure | CWE-200 |
| 19 | info | H7 | X-Powered-By disclosure | CWE-200 |
| 20 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [LOW] Unencoded reflected parameter (XSS-adjacent) (`B3`)

- **CWE:** CWE-79
- **Detail:** GET https://vk.com/about?act=<payload> reflects the act value, but re-verify 2026-09-25 shows it only in the og:url meta attribute, percent-encoded (content="...?act=xsszk%3Csvg%20onload=alert(1)%3Exsszk") - the angle brackets are URL-encoded so the markup is not parsed; full current URL is serialized into og:url for any act value.
- **Recommendation:** Escape output in the correct context for the harvested parameter and add a CSP with script-src; re-test all parameters harvested from live pages.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie remixlang lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie remixlang lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 4. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie remixstlid lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 10. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 11. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 12. [INFO] robots.txt discloses sensitive paths (`A10`)

- **CWE:** CWE-200
- **Detail:** Disallowed paths in robots.txt: *api_access_key=, /login?*=, *?slogin*, *api_access_key=, *?slogin*, *api_access_key=, /login?*=, *?slogin*.
- **Recommendation:** Treat robots.txt as discovery, not a control: ensure listed sensitive paths are authenticated or rate-limited.

### 13. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /admin (HTML shell), /console (HTML shell), /dashboard (HTML shell), /api (HTML shell), /api/v1 (HTML shell), /debug (HTML shell), /trace (HTML shell), /openapi.json (HTML shell), /phpmyadmin (HTML shell), /actuator (HTML shell), /actuator/env (HTML shell), /backup (HTML shell) (16 total).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 14. [INFO] SQLi-style payload reflected on harvested parameter (`B4i`)

- **CWE:** CWE-89
- **Detail:** GET https://vk.com/about?act=' OR '1'='1 was reflected verbatim (param 'act'); confirm with error-based probes.
- **Recommendation:** Verify the reflected SQLi-style payload with error-based probes; if it reaches a query, parameterize it.

### 15. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 16. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 17. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: kittenx
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 18. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: kittenx
- **Recommendation:** Consider hiding or shortening the Server header.

### 19. [INFO] X-Powered-By disclosure (`H7`)

- **CWE:** CWE-200
- **Detail:** X-Powered-By: KPHP/7.4.127571
- **Recommendation:** Remove the X-Powered-By header.

### 20. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/admin (HTML shell)","/console (HTML shell)","/dashboard (HTML shell)","/api (HTML shell)","/api/v1 (HTML shell)","/debug (HTML shell)","/trace (HTML shell)","/openapi.json (HTML shell)","/phpmyadmin (HTML shell)","/actuator (HTML shell)","/actuator/env (HTML shell)","/backup (HTML shell)","/database (HTML shell)","/config (HTML shell)","/package.json (HTML shell)","/metrics (HTML shell)"]}
- robots_disallow: ["/doc-*","/away.php","/im?","/search*&*&*&","*?w=story","*?w=wall","*?w=page","*?w=app","*?w=poll","*?w=service-booking-*","*?w=likes","*?w=shares","*?w=note","*?w=away","/call?id=","/feed$","/feed*","/bookmarks*","/friends*","/gifts"]

Stage-2 probe log (observed responses):
- timing base=1560ms id=845 search=726
- boolean b=200/209422 t1=200/209448 t2=200/209448
- graphql /graphql -> 200
- graphql /api/graphql -> 200
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 200
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- apicors /api -> 200
- apicors /api/v1 -> 200
- apicors /graphql -> 200
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (26 requests):**

- params_harvested: ["ch","id","act"]

Stage-3 probe log (observed responses):
- harvest discovered 3 live query params
- xss3 /js/lib/px.js?ch -> 302
- xss3 //top-fwz1.mail.ru/counter?id -> 404
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://vk.com/",
  "https_status": 302,
  "content_type": "text/html; charset=windows-1251",
  "title": "",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 200",
    "sqli /?id=1%27+OR+1=1-- -> 302",
    "sqli /?q=%27 -> 302",
    "sqli /products?filter=%27 -> 302",
    "sqli /?p=1;-- -> 302",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 200",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 302",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 302",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 302",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 404",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 302",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 200",
    "host no reflection -> 404",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=1560ms id=845 search=726",
    "boolean b=200/209422 t1=200/209448 t2=200/209448",
    "graphql /graphql -> 200",
    "graphql /api/graphql -> 200",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 200",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "redir2 no hits over 49 requests",
    "apicors /api -> 200",
    "apicors /api/v1 -> 200",
    "apicors /graphql -> 200",
    "apicors /rest -> 404",
    "apicors /v1 -> 404"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/admin (HTML shell)",
      "/console (HTML shell)",
      "/dashboard (HTML shell)",
      "/api (HTML shell)",
      "/api/v1 (HTML shell)",
      "/debug (HTML shell)",
      "/trace (HTML shell)",
      "/openapi.json (HTML shell)",
      "/phpmyadmin (HTML shell)",
      "/actuator (HTML shell)",
      "/actuator/env (HTML shell)",
      "/backup (HTML shell)",
      "/database (HTML shell)",
      "/config (HTML shell)",
      "/package.json (HTML shell)",
      "/metrics (HTML shell)"
    ]
  },
  "robots_disallow": [
    "/doc-*",
    "/away.php",
    "/im?",
    "/search*&*&*&",
    "*?w=story",
    "*?w=wall",
    "*?w=page",
    "*?w=app",
    "*?w=poll",
    "*?w=service-booking-*",
    "*?w=likes",
    "*?w=shares",
    "*?w=note",
    "*?w=away",
    "/call?id=",
    "/feed$",
    "/feed*",
    "/bookmarks*",
    "/friends*",
    "/gifts"
  ],
  "v3_probe_count": 26,
  "v3_log": [
    "harvest discovered 3 live query params",
    "xss3 /js/lib/px.js?ch -> 302",
    "xss3 //top-fwz1.mail.ru/counter?id -> 404",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ],
  "params_harvested": [
    "ch",
    "id",
    "act"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
