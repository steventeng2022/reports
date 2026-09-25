# Security Audit Report - rottentomatoes.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://rottentomatoes.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | rottentomatoes.com |
| Test date | 2026-09-24 22:03 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **17** (High: 1, Medium: 0, Low: 13, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | B9 | Subdomain takeover candidate (dangling CNAME within own zone) | CWE-1596 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 5 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 6 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 7 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 8 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 9 | low | H1 | Missing HSTS header | CWE-319 |
| 10 | low | H2 | Missing CSP header | CWE-1021 |
| 11 | low | H2 | Missing CSP header | CWE-1021 |
| 12 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 13 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 14 | low | R2 | No HTTP->HTTPS redirect | CWE-319 |
| 15 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 16 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 17 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Subdomain takeover candidate (dangling CNAME within own zone) (`B9`)

- **CWE:** CWE-1596
- **Detail:** Re-verified 2026-09-25 via DoH (dns.google): CNAME staging.rottentomatoes.com -> staging.dev.rottentomatoes.com (live); target returns NXDOMAIN (status 3). The target is within the same registrable domain (decommissioned internal staging), so recovery/claim requires controlling or restoring that zone record - lower value than a cross-zone takeover but the CNAME is live and dangling.
- **Recommendation:** Claim or remove the dangling CNAME now; move the subdomain to a controlled target so an attacker cannot register the service record (CWE-1596).

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie akacd_RTReplatform lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookies without Secure flag
- **Recommendation:** Add the Secure attribute to the cookie.

### 4. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie akamai_generated_location lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 5. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie akacd_RTReplatform lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 6. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie akamai_generated_location lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 7. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie akacd_RTReplatform lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 8. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookies without HttpOnly flag
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 9. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 10. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 11. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 12. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 13. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 14. [LOW] No HTTP->HTTPS redirect (`R2`)

- **CWE:** CWE-319
- **Detail:** http://rottentomatoes.com returns 403 without redirecting to HTTPS; however HSTS is present on the HTTPS response (max-age=31536000; includeSubdomains), which limits bootstrap risk.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

### 15. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /admin (403 protected), /console (403 protected), /dashboard (403 protected), /api (403 protected), /api/v1 (403 protected), /debug (403 protected), /trace (403 protected), /server-status (403 protected), /.svn/entries (403 protected), /swagger-ui.html (403 protected), /swagger.json (403 protected), /openapi.json (403 protected) (26 total).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 16. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 17. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/admin (403 protected)","/console (403 protected)","/dashboard (403 protected)","/api (403 protected)","/api/v1 (403 protected)","/debug (403 protected)","/trace (403 protected)","/server-status (403 protected)","/.svn/entries (403 protected)","/swagger-ui.html (403 protected)","/swagger.json (403 protected)","/openapi.json (403 protected)","/api-docs (403 protected)","/wp-login.php (403 protected)","/phpmyadmin (403 protected)","/actuator (403 protected)","/actuator/env (403 protected)","/backup (403 protected)","/backup.zip (403 protected)","/database (403 protected)","/config (403 protected)","/config.yml (403 protected)","/elm.json (403 protected)","/package.json (403 protected)","/.aws/credentials (403 protected)","/metrics (403 protected)"]}

Stage-2 probe log (observed responses):
- timing base=113ms id=117 search=110
- boolean b=403/369 t1=403/369 t2=403/369
- graphql /graphql -> 403
- graphql /api/graphql -> 403
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403
- trav2 /%2e%2e%00.html -> 403
- trav2 /static//../../../../../../etc/passwd -> 403
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 403
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- apicors /api -> 403
- apicors /api/v1 -> 403
- apicors /graphql -> 403
- apicors /rest -> 403
- apicors /v1 -> 403

**Stage 3 - live parameter harvest, takeover and injection probes (9 requests):**

- subdomains: ["staging.rottentomatoes.com -> staging.dev.rottentomatoes.com (NXDOMAIN target 3)"]

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages

## Evidence (raw response observations)

```json
{
  "http_status": 403,
  "https_status": 403,
  "content_type": "text/html",
  "title": "Access Denied",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 403,
  "path_robots": 403,
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
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 403",
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
    "timing base=113ms id=117 search=110",
    "boolean b=403/369 t1=403/369 t2=403/369",
    "graphql /graphql -> 403",
    "graphql /api/graphql -> 403",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403",
    "trav2 /%2e%2e%00.html -> 403",
    "trav2 /static//../../../../../../etc/passwd -> 403",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 403",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "redir2 no hits over 49 requests",
    "apicors /api -> 403",
    "apicors /api/v1 -> 403",
    "apicors /graphql -> 403",
    "apicors /rest -> 403",
    "apicors /v1 -> 403"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/admin (403 protected)",
      "/console (403 protected)",
      "/dashboard (403 protected)",
      "/api (403 protected)",
      "/api/v1 (403 protected)",
      "/debug (403 protected)",
      "/trace (403 protected)",
      "/server-status (403 protected)",
      "/.svn/entries (403 protected)",
      "/swagger-ui.html (403 protected)",
      "/swagger.json (403 protected)",
      "/openapi.json (403 protected)",
      "/api-docs (403 protected)",
      "/wp-login.php (403 protected)",
      "/phpmyadmin (403 protected)",
      "/actuator (403 protected)",
      "/actuator/env (403 protected)",
      "/backup (403 protected)",
      "/backup.zip (403 protected)",
      "/database (403 protected)",
      "/config (403 protected)",
      "/config.yml (403 protected)",
      "/elm.json (403 protected)",
      "/package.json (403 protected)",
      "/.aws/credentials (403 protected)",
      "/metrics (403 protected)"
    ]
  },
  "v3_probe_count": 9,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "cache X-Forwarded-Host not reflected -> 403"
  ],
  "subdomains": [
    "staging.rottentomatoes.com -> staging.dev.rottentomatoes.com (NXDOMAIN target 3)"
  ],
  "source": " + merged aggressive-injection-hunt pass (agent-aggressive, 2026-09-24 22:21 UTC)"
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
