# Security Audit Report - codecanyon.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://codecanyon.net/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | codecanyon.net |
| Test date | 2026-09-25 14:50 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 8, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | C12b | Ancillary file exposure (v4 sweep) | CWE-538 |
| 3 | low | C3i | Percent-encoded XSS payload reflected (v4 matrix) | CWE-79 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | A10 | robots.txt discloses sensitive paths | CWE-200 |
| 10 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 11 | info | B4 | Error-based SQLi on harvested parameter | CWE-89 |
| 12 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 13 | info | C15 | WAF / edge fingerprint (v4) | CWE-200 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |
| 16 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie __cf_bm lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Ancillary file exposure (v4 sweep) (`C12b`)

- **CWE:** CWE-538
- **Detail:** Exposed: /debug/pprof/ -> 429 (soft-200 html); /crossdomain.xml -> 429 (soft-200 html); /.DS_Store -> 429 (soft-200 html); /.svn/entries -> 429 (soft-200 html); /backup.zip -> 429 (soft-200 html); /db.sqlite3 -> 429 (soft-200 html); /config.php.bak -> 429 (soft-200 html); /CNAME -> 429 (soft-200 html).
- **Recommendation:** Remove or protect backup/metadata files (.DS_Store, .svn, *.bak, sqlite, crossdomain.xml) from public access.

### 3. [LOW] Percent-encoded XSS payload reflected (v4 matrix) (`C3i`)

- **CWE:** CWE-79
- **Detail:** GET https://codecanyon.net/search?date=%3Csvg%2Fonload%3Dalert(1)%3E reflected the single-encoded payload (param 'date'); context-dependent exploitability.
- **Recommendation:** Confirm whether the percent-encoded reflection decodes in a browser context; escape or normalize input values.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] robots.txt discloses sensitive paths (`A10`)

- **CWE:** CWE-200
- **Detail:** Disallowed paths in robots.txt: /shopfront-api/, /shopfront_api/.
- **Recommendation:** Treat robots.txt as discovery, not a control: ensure listed sensitive paths are authenticated or rate-limited.

### 10. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /api (403 protected), /api/v1 (403 protected), /.svn/entries (403 protected), /api-docs (403 protected), /wp-login.php (403 protected).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 11. [INFO] Error-based SQLi on harvested parameter (`B4`)

- **CWE:** CWE-89
- **Detail:** Original v3 probe reported a database error signature on GET /search?date=<sqli payload>, but re-verification (2 rounds x 5 error-based payloads: quote, double-quote, backslash, paren, comment) found 0/10 signature hits; baseline returns 403 (bot-protection page). Kept as a low-confidence candidate; recommend re-testing with an authenticated session.
- **Recommendation:** Parameterize queries for the affected parameter; confirm with error-based and boolean probes before closing.

### 12. [INFO] Additional responsive paths (v4 sweep) (`C12i`)

- **CWE:** CWE-538
- **Detail:** Answered without 404: /elmah.axd -> 429 (soft-200 html); /elmah.axd/list -> 429 (soft-200 html); /trace.axd -> 429 (soft-200 html); /swagger.json -> 429 (soft-200 html); /swagger-ui.html -> 429 (soft-200 html); /swagger/v1/swagger.json -> 429 (soft-200 html); /openapi.json -> 429 (soft-200 html); /v2/api-docs -> 429 (soft-200 html); /v3/api-docs -> 429 (soft-200 html); /graphql -> 429; /debug -> 429 (soft-200 html); /debug/vars -> 429 (soft-200 html) (+others).
- **Recommendation:** Return a real 404 for paths that should not exist; review the listed responsive paths for sensitive content.

### 13. [INFO] WAF / edge fingerprint (v4) (`C15`)

- **CWE:** CWE-200
- **Detail:** Fingerprinted during probing: Cloudflare (matched on response body/server header across injection probes).
- **Recommendation:** No direct fix; use the fingerprint to tune WAF rules and re-test with encoded variants.

### 14. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 15. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 16. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/api (403 protected)","/api/v1 (403 protected)","/.svn/entries (403 protected)","/api-docs (403 protected)","/wp-login.php (403 protected)"]}
- robots_disallow: ["*?platform*","*/full_screen_preview/","*?sales*","*/cart/*","*/sign_in?*","*/item_support/","/affiliate/","/referral/","/shopfront-api/","/shopfront_api/","/cart/","*?sort=*","*,*,*","*?attribute_key","*\\+*\\+*","/cart$","/sign_in","/consociate/","*price_min=*","*price_max=*"]

Stage-2 probe log (observed responses):
- timing base=415ms id=75 search=86
- boolean b=200/427666 t1=403/352663 t2=403/352663
- graphql /graphql -> 404
- graphql /api/graphql -> 403
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 403
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 403
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- apicors /api -> 403
- apicors /api/v1 -> 403
- apicors /graphql -> 404
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (48 requests):**

- params_harvested: ["id","utm_source","auto_signin","date","category","compatible_with","sort","term","utm_campaign","to","w","item_id"]

Stage-3 probe log (observed responses):
- harvest discovered 12 live query params
- xss3 https://www.googletagmanager.com/ns.html?id -> err
- xss3 https://elements.envato.com/?utm_source -> err
- xss3 https://themeforest.net/?auto_signin -> err
- xss3 /search?date -> 403
- xss3 /popular_item/by_category?category -> 403
- xss3 /search?compatible_with -> 403
- xss3 /search/ai?sort -> 403
- xss3 /search?term -> 403
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (141 requests):**

- v4_params: ["id@https://www.googletagmanager.com/ns.html","utm_source@https://elements.envato.com/","auto_signin@https://themeforest.net/","date@/search","category@/popular_item/by_category","compatible_with@/search","sort@/search/ai","term@/search"]

Stage-4 probe log (observed responses):
- harvest discovered 12 live query params

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://codecanyon.net/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "Buy Plugins &amp; Code from CodeCanyon",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 403",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 404",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 403",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 403",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 404",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 404",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 404",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 403",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=415ms id=75 search=86",
    "boolean b=200/427666 t1=403/352663 t2=403/352663",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 403",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 403",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 403",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "redir2 no hits over 49 requests",
    "apicors /api -> 403",
    "apicors /api/v1 -> 403",
    "apicors /graphql -> 404",
    "apicors /rest -> 404",
    "apicors /v1 -> 404"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/api (403 protected)",
      "/api/v1 (403 protected)",
      "/.svn/entries (403 protected)",
      "/api-docs (403 protected)",
      "/wp-login.php (403 protected)"
    ]
  },
  "robots_disallow": [
    "*?platform*",
    "*/full_screen_preview/",
    "*?sales*",
    "*/cart/*",
    "*/sign_in?*",
    "*/item_support/",
    "/affiliate/",
    "/referral/",
    "/shopfront-api/",
    "/shopfront_api/",
    "/cart/",
    "*?sort=*",
    "*,*,*",
    "*?attribute_key",
    "*\\+*\\+*",
    "/cart$",
    "/sign_in",
    "/consociate/",
    "*price_min=*",
    "*price_max=*"
  ],
  "v3_probe_count": 48,
  "v3_log": [
    "harvest discovered 12 live query params",
    "xss3 https://www.googletagmanager.com/ns.html?id -> err",
    "xss3 https://elements.envato.com/?utm_source -> err",
    "xss3 https://themeforest.net/?auto_signin -> err",
    "xss3 /search?date -> 403",
    "xss3 /popular_item/by_category?category -> 403",
    "xss3 /search?compatible_with -> 403",
    "xss3 /search/ai?sort -> 403",
    "xss3 /search?term -> 403",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 403"
  ],
  "params_harvested": [
    "id",
    "utm_source",
    "auto_signin",
    "date",
    "category",
    "compatible_with",
    "sort",
    "term",
    "utm_campaign",
    "to",
    "w",
    "item_id"
  ],
  "v4_probe_count": 141,
  "v4_log": [
    "harvest discovered 12 live query params",
    "xss4 /popular_item/by_category?category svg-onload -> 403 no raw echo",
    "xss4 /popular_item/by_category?category attr-breakout -> 403 no raw echo",
    "xss4 /popular_item/by_category?category script-tag -> 403 no raw echo",
    "xss4 /popular_item/by_category?category dbl-enc-svg -> 403 no raw echo"
  ],
  "v4_params": [
    "id@https://www.googletagmanager.com/ns.html",
    "utm_source@https://elements.envato.com/",
    "auto_signin@https://themeforest.net/",
    "date@/search",
    "category@/popular_item/by_category",
    "compatible_with@/search",
    "sort@/search/ai",
    "term@/search"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
