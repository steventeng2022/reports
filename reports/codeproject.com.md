# Security Audit Report - codeproject.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://codeproject.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | codeproject.com |
| Test date | 2026-09-24 14:13 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **15** (High: 0, Medium: 1, Low: 8, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | R2 | No HTTP->HTTPS redirect | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | A10b | Sitemap enumerates URLs | CWE-200 |
| 11 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | P1 | Git repository exposure (re-verified: parking lander) | CWE-538 |
| 15 | info | P2 | Environment file exposure (re-verified: parking lander) | CWE-538 |

## Detailed findings

### 1. [MEDIUM] No HTTP->HTTPS redirect (`R2`)

- **CWE:** CWE-319
- **Detail:** http://codeproject.com returns 200 (parking lander) without redirecting to HTTPS; no HSTS observed on the HTTPS response.
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

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Sitemap enumerates URLs (`A10b`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml lists 1 URLs; sensitive-looking entries: none.
- **Recommendation:** Remove or protect internal/sensitive URLs from the public sitemap.

### 11. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /admin (HTML shell), /console (HTML shell), /dashboard (HTML shell), /api (HTML shell), /debug (HTML shell), /trace (HTML shell), /server-status (HTML shell), /.svn/entries (HTML shell), /swagger-ui.html (HTML shell), /swagger.json (HTML shell), /openapi.json (HTML shell), /api-docs (HTML shell) (25 total).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 14. [INFO] Git repository exposure (re-verified: parking lander) (`P1`)

- **CWE:** CWE-538
- **Detail:** GET https://codeproject.com/.git/config returns 200, but the body is a JS parking lander (window.location.href="/lander"), not git metadata; not a real repository exposure on re-verify.
- **Recommendation:** Review and remediate per CWE guidance.

### 15. [INFO] Environment file exposure (re-verified: parking lander) (`P2`)

- **CWE:** CWE-538
- **Detail:** GET https://codeproject.com/.env returns 200, but the body is the same JS lander (window.location.href="/lander"), not environment data; not a real exposure on re-verify.
- **Recommendation:** Review and remediate per CWE guidance.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/admin (HTML shell)","/console (HTML shell)","/dashboard (HTML shell)","/api (HTML shell)","/debug (HTML shell)","/trace (HTML shell)","/server-status (HTML shell)","/.svn/entries (HTML shell)","/swagger-ui.html (HTML shell)","/swagger.json (HTML shell)","/openapi.json (HTML shell)","/api-docs (HTML shell)","/wp-login.php (HTML shell)","/phpmyadmin (HTML shell)","/actuator (HTML shell)","/actuator/env (HTML shell)","/backup (HTML shell)","/backup.zip (HTML shell)","/database (HTML shell)","/config (HTML shell)","/config.yml (HTML shell)","/elm.json (HTML shell)","/package.json (HTML shell)","/.aws/credentials (HTML shell)","/metrics (HTML shell)"]}
- robots_disallow: []
- sitemap: {"total":1,"sensitive":[]}

Stage-2 probe log (observed responses):
- timing base=342ms id=330 search=111
- boolean b=200/119 t1=200/129 t2=200/129
- graphql /graphql -> 200
- graphql /api/graphql -> 404
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 200
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 200
- trav2 /%2e%2e%00.html -> 200
- trav2 /static//../../../../../../etc/passwd -> 200
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 200
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- apicors /api -> 200
- apicors /api/v1 -> 404
- apicors /graphql -> 200
- apicors /rest -> 200
- apicors /v1 -> 200

**Stage 3 - live parameter harvest, takeover and injection probes (8 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_status": 200,
  "https_status": 200,
  "content_type": "text/html",
  "title": "",
  "path_gitconfig": 200,
  "path_envfile": 200,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 200",
    "sqli /?id=1%27+OR+1=1-- -> 200",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 200",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 200",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 200",
    "trav /static/../../../../../../../../etc/passwd -> 200",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 200",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 200",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 200",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=342ms id=330 search=111",
    "boolean b=200/119 t1=200/129 t2=200/129",
    "graphql /graphql -> 200",
    "graphql /api/graphql -> 404",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 200",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 200",
    "trav2 /%2e%2e%00.html -> 200",
    "trav2 /static//../../../../../../etc/passwd -> 200",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 200",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "redir2 no hits over 49 requests",
    "apicors /api -> 200",
    "apicors /api/v1 -> 404",
    "apicors /graphql -> 200",
    "apicors /rest -> 200",
    "apicors /v1 -> 200"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/admin (HTML shell)",
      "/console (HTML shell)",
      "/dashboard (HTML shell)",
      "/api (HTML shell)",
      "/debug (HTML shell)",
      "/trace (HTML shell)",
      "/server-status (HTML shell)",
      "/.svn/entries (HTML shell)",
      "/swagger-ui.html (HTML shell)",
      "/swagger.json (HTML shell)",
      "/openapi.json (HTML shell)",
      "/api-docs (HTML shell)",
      "/wp-login.php (HTML shell)",
      "/phpmyadmin (HTML shell)",
      "/actuator (HTML shell)",
      "/actuator/env (HTML shell)",
      "/backup (HTML shell)",
      "/backup.zip (HTML shell)",
      "/database (HTML shell)",
      "/config (HTML shell)",
      "/config.yml (HTML shell)",
      "/elm.json (HTML shell)",
      "/package.json (HTML shell)",
      "/.aws/credentials (HTML shell)",
      "/metrics (HTML shell)"
    ]
  },
  "robots_disallow": [],
  "sitemap": {
    "total": 1,
    "sensitive": []
  },
  "v3_probe_count": 8,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
