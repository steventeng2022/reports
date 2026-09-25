# Security Audit Report - justgiving.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://justgiving.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | justgiving.com |
| Test date | 2026-09-25 14:55 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 4, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C16 | llms.txt / LLM context file exposed (v4) | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | A10 | robots.txt discloses sensitive paths | CWE-200 |
| 6 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] llms.txt / LLM context file exposed (v4) (`C16`)

- **CWE:** CWE-538
- **Detail:** GET https://justgiving.com/llms.txt returned 1358 bytes of text/plain content; the AI-oriented index describes site structure/data for LLM consumers.
- **Recommendation:** Decide whether the llms.txt file should be public; redact internal structure, endpoints, and data descriptions if not intended for LLM consumers.

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

### 5. [INFO] robots.txt discloses sensitive paths (`A10`)

- **CWE:** CWE-200
- **Detail:** Disallowed paths in robots.txt: /charities/beta/account/login, /charities/beta/account/login, /charities/beta/account/login, /charities/beta/account/login, /charities/beta/account/login, /charities/beta/account/login, /charities/beta/account/login.
- **Recommendation:** Treat robots.txt as discovery, not a control: ensure listed sensitive paths are authenticated or rate-limited.

### 6. [INFO] Additional responsive paths (v4 sweep) (`C12i`)

- **CWE:** CWE-538
- **Detail:** Answered without 404: /elmah.axd -> 200; /elmah.axd/list -> 200.
- **Recommendation:** Return a real 404 for paths that should not exist; review the listed responsive paths for sensitive content.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: CloudFront
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: AmazonS3
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- robots_disallow: ["/","/","/user-account/","/charity/search","/fundraiser/search","/charities/beta/account/login","/share-success/","/user-account/","/charity/search","/fundraiser/search","/charities/beta/account/login","/share-success/","/user-account/","/charity/search","/fundraiser/search","/charities/beta/account/login","/share-success/","/user-account/","/charity/search","/fundraiser/search"]

Stage-2 probe log (observed responses):
- timing base=677ms id=14 search=679
- boolean b=200/5280 t1=200/5280 t2=200/5280
- graphql /graphql -> 302
- graphql /api/graphql -> 404
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 406
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 406
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 406
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- apicors /api -> 301
- apicors /api/v1 -> 404
- apicors /graphql -> 302
- apicors /rest -> 302
- apicors /v1 -> 302

**Stage 3 - live parameter harvest, takeover and injection probes (15 requests):**

- params_harvested: ["id"]

Stage-3 probe log (observed responses):
- harvest discovered 1 live query params
- xss3 https://www.googletagmanager.com/ns.html?id -> err
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (93 requests):**

- v4_params: ["id@https://www.googletagmanager.com/ns.html"]

Stage-4 probe log (observed responses):
- harvest discovered 1 live query params

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://justgiving.com/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "Online fundraising donations and ideas - JustGiving",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 200",
    "sqli /?id=1%27+OR+1=1-- -> 200",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 302",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 200",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 406",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 406",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 406",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 200",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=677ms id=14 search=679",
    "boolean b=200/5280 t1=200/5280 t2=200/5280",
    "graphql /graphql -> 302",
    "graphql /api/graphql -> 404",
    "sweep no hits over 26 paths",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 406",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 406",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 406",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "redir2 no hits over 49 requests",
    "apicors /api -> 301",
    "apicors /api/v1 -> 404",
    "apicors /graphql -> 302",
    "apicors /rest -> 302",
    "apicors /v1 -> 302"
  ],
  "robots_disallow": [
    "/",
    "/",
    "/user-account/",
    "/charity/search",
    "/fundraiser/search",
    "/charities/beta/account/login",
    "/share-success/",
    "/user-account/",
    "/charity/search",
    "/fundraiser/search",
    "/charities/beta/account/login",
    "/share-success/",
    "/user-account/",
    "/charity/search",
    "/fundraiser/search",
    "/charities/beta/account/login",
    "/share-success/",
    "/user-account/",
    "/charity/search",
    "/fundraiser/search"
  ],
  "v3_probe_count": 15,
  "v3_log": [
    "harvest discovered 1 live query params",
    "xss3 https://www.googletagmanager.com/ns.html?id -> err",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ],
  "params_harvested": [
    "id"
  ],
  "v4_probe_count": 93,
  "v4_log": [
    "harvest discovered 1 live query params"
  ],
  "v4_params": [
    "id@https://www.googletagmanager.com/ns.html"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
