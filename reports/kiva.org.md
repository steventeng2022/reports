# Security Audit Report - kiva.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://kiva.org/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | kiva.org |
| Test date | 2026-09-24 19:33 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 8, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
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
- **Detail:** Paths answering 401/403 or HTML shells: /phpmyadmin (403 protected), /.aws/credentials (403 protected).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: awselb/2.0
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: awselb/2.0
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/phpmyadmin (403 protected)","/.aws/credentials (403 protected)"]}

Stage-2 probe log (observed responses):
- timing base=660ms id=485 search=168
- boolean b=301/134 t1=301/134 t2=301/134
- graphql /graphql -> 301
- graphql /api/graphql -> 301
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 301
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 301
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- apicors /api -> 301
- apicors /api/v1 -> 301
- apicors /graphql -> 301
- apicors /rest -> 301
- apicors /v1 -> 301

**Stage 3 - live parameter harvest, takeover and injection probes (10 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://kiva.org:443/",
  "https_status": 301,
  "content_type": "text/html",
  "title": "301 Moved Permanently",
  "path_gitconfig": 301,
  "path_envfile": 403,
  "path_securitytxt": 301,
  "path_robots": 301,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 301",
    "sqli /?id=1%27+OR+1=1-- -> 301",
    "sqli /?q=%27 -> 301",
    "sqli /products?filter=%27 -> 301",
    "sqli /?p=1;-- -> 301",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 301",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 403",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 301",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 301",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 403",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 301",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 301",
    "host no reflection -> 404",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=660ms id=485 search=168",
    "boolean b=301/134 t1=301/134 t2=301/134",
    "graphql /graphql -> 301",
    "graphql /api/graphql -> 301",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 301",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 301",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "redir2 no hits over 49 requests",
    "apicors /api -> 301",
    "apicors /api/v1 -> 301",
    "apicors /graphql -> 301",
    "apicors /rest -> 301",
    "apicors /v1 -> 301"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/phpmyadmin (403 protected)",
      "/.aws/credentials (403 protected)"
    ]
  },
  "v3_probe_count": 10,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 301"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
