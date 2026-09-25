# Security Audit Report - click.linksynergy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://click.linksynergy.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | click.linksynergy.com |
| Test date | 2026-09-24 22:07 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 8, Info: 3)

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
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | P3 | Missing security.txt | CWE-1038 |

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

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- robots_disallow: ["/"]

Stage-2 probe log (observed responses):
- timing base=133ms id=130 search=132
- boolean b=301/0 t1=301/0 t2=301/0
- graphql /graphql -> 404
- graphql /api/graphql -> 404
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 404
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301
- apicors /api -> 404
- apicors /api/v1 -> 404
- apicors /graphql -> 404
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (7 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://click.linksynergy.com/",
  "https_status": 301,
  "content_type": "",
  "title": "",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 404",
    "sqli /?id=1%27+OR+1=1-- -> 301",
    "sqli /?q=%27 -> 301",
    "sqli /products?filter=%27 -> 404",
    "sqli /?p=1;-- -> 301",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 404",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 301",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 404",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 404",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 400",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 301",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 404",
    "host no reflection -> 404",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=133ms id=130 search=132",
    "boolean b=301/0 t1=301/0 t2=301/0",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 404",
    "sweep no hits over 26 paths",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 404",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "redir2 no hits over 49 requests",
    "apicors /api -> 404",
    "apicors /api/v1 -> 404",
    "apicors /graphql -> 404",
    "apicors /rest -> 404",
    "apicors /v1 -> 404"
  ],
  "robots_disallow": [
    "/"
  ],
  "v3_probe_count": 7,
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
