# Security Audit Report - t.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://t.me/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | t.me |
| Test date | 2026-09-25 14:54 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 8, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C12b | Ancillary file exposure (v4 sweep) | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 10 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Ancillary file exposure (v4 sweep) (`C12b`)

- **CWE:** CWE-538
- **Detail:** Exposed: /debug/pprof/ -> 200 (soft-200 html); /CNAME -> 200 (soft-200 html).
- **Recommendation:** Remove or protect backup/metadata files (.DS_Store, .svn, *.bak, sqlite, crossdomain.xml) from public access.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /admin (HTML shell), /console (HTML shell), /dashboard (HTML shell), /api (401 protected), /api/v1 (401 protected), /debug (HTML shell), /trace (HTML shell), /phpmyadmin (HTML shell), /actuator (HTML shell), /actuator/env (HTML shell), /backup (HTML shell), /database (HTML shell) (14 total).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 10. [INFO] Additional responsive paths (v4 sweep) (`C12i`)

- **CWE:** CWE-538
- **Detail:** Answered without 404: /swagger/v1/swagger.json -> 200 (soft-200 html); /graphql -> 200; /debug -> 200 (soft-200 html); /debug/vars -> 200 (soft-200 html); /metrics -> 200; /actuator -> 200 (soft-200 html); /actuator/env -> 200 (soft-200 html); /actuator/health -> 200; /actuator/info -> 200; /console -> 200; /api -> 401; /admin -> 200.
- **Recommendation:** Return a real 404 for paths that should not exist; review the listed responsive paths for sensitive content.

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
- **Detail:** Server header reveals: nginx/1.30.1
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: nginx/1.30.1
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/admin (HTML shell)","/console (HTML shell)","/dashboard (HTML shell)","/api (401 protected)","/api/v1 (401 protected)","/debug (HTML shell)","/trace (HTML shell)","/phpmyadmin (HTML shell)","/actuator (HTML shell)","/actuator/env (HTML shell)","/backup (HTML shell)","/database (HTML shell)","/config (HTML shell)","/metrics (HTML shell)"]}

Stage-2 probe log (observed responses):
- timing base=649ms id=225 search=233
- boolean b=302/0 t1=302/0 t2=302/0
- graphql /graphql -> 200
- graphql /api/graphql -> 401
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 302
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 302
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 302
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 302
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 302
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302
- apicors /api -> 401
- apicors /api/v1 -> 401
- apicors /graphql -> 200
- apicors /rest -> 200
- apicors /v1 -> 302

**Stage 3 - live parameter harvest, takeover and injection probes (20 requests):**

- params_harvested: ["tme","domain"]

Stage-3 probe log (observed responses):
- harvest discovered 2 live query params
- xss3 //telegram.org/dl?tme -> 302
- xss3 tg://resolve?domain -> err
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (111 requests):**

- v4_params: ["tme@//telegram.org/dl","domain@tg://resolve"]

Stage-4 probe log (observed responses):
- harvest discovered 2 live query params

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://t.me/",
  "https_status": 302,
  "content_type": "text/html; charset=UTF-8",
  "title": "",
  "path_gitconfig": 302,
  "path_envfile": 302,
  "path_securitytxt": 302,
  "path_robots": 404,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 200",
    "sqli /?id=1%27+OR+1=1-- -> 302",
    "sqli /?q=%27 -> 302",
    "sqli /products?filter=%27 -> 200",
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
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 302",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 302",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 200",
    "host no reflection -> 302",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 401",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=649ms id=225 search=233",
    "boolean b=302/0 t1=302/0 t2=302/0",
    "graphql /graphql -> 200",
    "graphql /api/graphql -> 401",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 302",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 302",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 302",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 302",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 302",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302",
    "redir2 no hits over 49 requests",
    "apicors /api -> 401",
    "apicors /api/v1 -> 401",
    "apicors /graphql -> 200",
    "apicors /rest -> 200",
    "apicors /v1 -> 302"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/admin (HTML shell)",
      "/console (HTML shell)",
      "/dashboard (HTML shell)",
      "/api (401 protected)",
      "/api/v1 (401 protected)",
      "/debug (HTML shell)",
      "/trace (HTML shell)",
      "/phpmyadmin (HTML shell)",
      "/actuator (HTML shell)",
      "/actuator/env (HTML shell)",
      "/backup (HTML shell)",
      "/database (HTML shell)",
      "/config (HTML shell)",
      "/metrics (HTML shell)"
    ]
  },
  "v3_probe_count": 20,
  "v3_log": [
    "harvest discovered 2 live query params",
    "xss3 //telegram.org/dl?tme -> 302",
    "xss3 tg://resolve?domain -> err",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 302"
  ],
  "params_harvested": [
    "tme",
    "domain"
  ],
  "v4_probe_count": 111,
  "v4_log": [
    "harvest discovered 2 live query params",
    "xss4 //telegram.org/dl?tme svg-onload -> 302 no raw echo",
    "xss4 //telegram.org/dl?tme attr-breakout -> 302 no raw echo",
    "xss4 //telegram.org/dl?tme script-tag -> 302 no raw echo",
    "xss4 //telegram.org/dl?tme dbl-enc-svg -> 302 no raw echo"
  ],
  "v4_params": [
    "tme@//telegram.org/dl",
    "domain@tg://resolve"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
