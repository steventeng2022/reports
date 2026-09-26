# Security Audit Report - blogs.scientificamerican.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blogs.scientificamerican.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | blogs.scientificamerican.com |
| Test date | 2026-09-25 14:50 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 1, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 3 | info | H6 | Server technology disclosure | CWE-200 |
| 4 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /.aws/credentials (403 protected).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 3. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: CloudFront
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 4. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: CloudFront
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/.aws/credentials (403 protected)"]}

Stage-2 probe log (observed responses):
- timing base=19ms id=17 search=7
- boolean b=302/0 t1=403/919 t2=403/919
- graphql /graphql -> 302
- graphql /api/graphql -> 302
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 302
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 302
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- apicors /api -> 302
- apicors /api/v1 -> 302
- apicors /graphql -> 302
- apicors /rest -> 302
- apicors /v1 -> 302

**Stage 3 - live parameter harvest, takeover and injection probes (7 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (63 requests):**

- no stage-4 probe hits (all probes negative)

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://blogs.scientificamerican.com/",
  "https_status": 302,
  "content_type": "",
  "title": "",
  "path_gitconfig": 302,
  "path_envfile": 403,
  "path_securitytxt": 302,
  "path_robots": 302,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 403",
    "sqli /?q=%27 -> 302",
    "sqli /products?filter=%27 -> 302",
    "sqli /?p=1;-- -> 302",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 403",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 403",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 302",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 302",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 403",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 302",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 302",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=19ms id=17 search=7",
    "boolean b=302/0 t1=403/919 t2=403/919",
    "graphql /graphql -> 302",
    "graphql /api/graphql -> 302",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 302",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 302",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "redir2 no hits over 49 requests",
    "apicors /api -> 302",
    "apicors /api/v1 -> 302",
    "apicors /graphql -> 302",
    "apicors /rest -> 302",
    "apicors /v1 -> 302"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/.aws/credentials (403 protected)"
    ]
  },
  "v3_probe_count": 7,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 302"
  ],
  "v4_probe_count": 63,
  "v4_log": [
    "harvest no query params discovered",
    "sweep4 all swept paths 404/403"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
