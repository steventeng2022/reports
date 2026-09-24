# Security Audit Report - slideshare.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://slideshare.net/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | slideshare.net |
| Test date | 2026-09-24 09:36 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 11, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C1 | Cookie without Secure flag | CWE-614 |
| 4 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 5 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | low | H4 | No clickjacking protection | CWE-1023 |
| 11 | low | H4 | No clickjacking protection | CWE-1023 |
| 12 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie browser_id lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie _fs_ch_st_FSBmUei20MqUiJb9 lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie browser_id lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 4. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie browser_id lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 5. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie browser_id lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

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

### 12. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /admin (HTML shell), /dashboard (HTML shell), /api/v1 (HTML shell), /trace (HTML shell), /swagger.json (HTML shell), /api-docs (HTML shell), /actuator/env (HTML shell), /backup.zip (HTML shell), /config (HTML shell), /elm.json (HTML shell).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 14. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 15. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Varnish
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/admin (HTML shell)","/dashboard (HTML shell)","/api/v1 (HTML shell)","/trace (HTML shell)","/swagger.json (HTML shell)","/api-docs (HTML shell)","/actuator/env (HTML shell)","/backup.zip (HTML shell)","/config (HTML shell)","/elm.json (HTML shell)"]}

Stage-2 probe log (observed responses):
- timing base=514ms id=116 search=138
- boolean b=301/162 t1=406/0 t2=301/162
- graphql /graphql -> 200
- graphql /api/graphql -> 301
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 200
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406
- trav2 /%2e%2e%00.html -> 200
- trav2 /static//../../../../../../etc/passwd -> 301
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 406
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 406
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 406
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 406
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 406
- apicors /api -> 200
- apicors /api/v1 -> 301
- apicors /graphql -> 200
- apicors /rest -> 301
- apicors /v1 -> 200

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://slideshare.net/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "Client Challenge",
  "path_gitconfig": 406,
  "path_envfile": 406,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 406",
    "sqli /?id=1%27+OR+1=1-- -> 406",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 200",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 406",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 406",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 406",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 406",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 406",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 406",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 406",
    "trav /static/../../../../../../../../etc/passwd -> 200",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 200",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 406",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 200",
    "host no reflection -> 421",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=514ms id=116 search=138",
    "boolean b=301/162 t1=406/0 t2=301/162",
    "graphql /graphql -> 200",
    "graphql /api/graphql -> 301",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 200",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406",
    "trav2 /%2e%2e%00.html -> 200",
    "trav2 /static//../../../../../../etc/passwd -> 301",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 406",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 406",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 406",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 406",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 406",
    "redir2 no hits over 49 requests",
    "apicors /api -> 200",
    "apicors /api/v1 -> 301",
    "apicors /graphql -> 200",
    "apicors /rest -> 301",
    "apicors /v1 -> 200"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/admin (HTML shell)",
      "/dashboard (HTML shell)",
      "/api/v1 (HTML shell)",
      "/trace (HTML shell)",
      "/swagger.json (HTML shell)",
      "/api-docs (HTML shell)",
      "/actuator/env (HTML shell)",
      "/backup.zip (HTML shell)",
      "/config (HTML shell)",
      "/elm.json (HTML shell)"
    ]
  }
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a two-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection, XSS, traversal, CORS and redirect probes, up to ~100 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
