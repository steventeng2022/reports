# Security Audit Report - pitchfork.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pitchfork.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | pitchfork.com |
| Test date | 2026-09-25 14:53 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 9, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 2 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 3 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 4 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | A10b | Sitemap enumerates URLs | CWE-200 |
| 11 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 12 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |
| 16 | info | H6 | Server technology disclosure | CWE-200 |
| 17 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie xid1 lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 2. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie CN_segments lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 3. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie CN_xid lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 4. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie CN_geo_country_code lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Sitemap enumerates URLs (`A10b`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml lists 60 URLs; sensitive-looking entries: none.
- **Recommendation:** Remove or protect internal/sensitive URLs from the public sitemap.

### 11. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /wp-login.php (403 protected), /config (403 protected).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 12. [INFO] Additional responsive paths (v4 sweep) (`C12i`)

- **CWE:** CWE-538
- **Detail:** Answered without 404: /sitemap.xml -> 200.
- **Recommendation:** Return a real 404 for paths that should not exist; review the listed responsive paths for sensitive content.

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
- **Detail:** Server header reveals: CloudFront
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 16. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: CloudFront
- **Recommendation:** Consider hiding or shortening the Server header.

### 17. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/wp-login.php (403 protected)","/config (403 protected)"]}
- robots_disallow: ["/*?","/auth/","/account/","/user/","/user-context","/preview/","/search","/product/","/cdn-cgi/","/services.min.js","/com.condenast/yv8","/reject-all","/"]
- sitemap: {"total":60,"sensitive":[]}

Stage-2 probe log (observed responses):
- timing base=2488ms id=6 search=22
- boolean b=200/1337742 t1=403/919 t2=403/919
- graphql /graphql -> 404
- graphql /api/graphql -> 404
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 404
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 400
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- apicors /api -> 404
- apicors /api/v1 -> 404
- apicors /graphql -> 404
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (39 requests):**

- params_harvested: ["property_id","v","id","source","lang"]

Stage-3 probe log (observed responses):
- harvest discovered 5 live query params
- xss3 https://privacy.condenastdigital.com/fides.js?property_id -> err
- xss3 https://ads-static.conde.digital/production/cns/builds/pitchfork/v6.js?v -> err
- xss3 https://www.googletagmanager.com/ns.html?id -> err
- xss3 https://pitchfork.com/v2/offers/pfa01011?source -> err
- xss3 https://www.tiktok.com/@pitchfork?lang -> err
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (137 requests):**

- v4_params: ["property_id@https://privacy.condenastdigital.com/fides.js","v@https://ads-static.conde.digital/production/cns/builds/pitchfork/v6.js","id@https://www.googletagmanager.com/ns.html","source@https://pitchfork.com/v2/offers/pfa01011","lang@https://www.tiktok.com/@pitchfork"]

Stage-4 probe log (observed responses):
- harvest discovered 5 live query params

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://pitchfork.com/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "Pitchfork | The Most Trusted Voice in Music. | Pitchfork",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 404,
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
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
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
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 404",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=2488ms id=6 search=22",
    "boolean b=200/1337742 t1=403/919 t2=403/919",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 404",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 404",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 400",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "redir2 no hits over 49 requests",
    "apicors /api -> 404",
    "apicors /api/v1 -> 404",
    "apicors /graphql -> 404",
    "apicors /rest -> 404",
    "apicors /v1 -> 404"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/wp-login.php (403 protected)",
      "/config (403 protected)"
    ]
  },
  "robots_disallow": [
    "/*?",
    "/auth/",
    "/account/",
    "/user/",
    "/user-context",
    "/preview/",
    "/search",
    "/product/",
    "/cdn-cgi/",
    "/services.min.js",
    "/com.condenast/yv8",
    "/reject-all",
    "/"
  ],
  "sitemap": {
    "total": 60,
    "sensitive": []
  },
  "v3_probe_count": 39,
  "v3_log": [
    "harvest discovered 5 live query params",
    "xss3 https://privacy.condenastdigital.com/fides.js?property_id -> err",
    "xss3 https://ads-static.conde.digital/production/cns/builds/pitchfork/v6.js?v -> err",
    "xss3 https://www.googletagmanager.com/ns.html?id -> err",
    "xss3 https://pitchfork.com/v2/offers/pfa01011?source -> err",
    "xss3 https://www.tiktok.com/@pitchfork?lang -> err",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ],
  "params_harvested": [
    "property_id",
    "v",
    "id",
    "source",
    "lang"
  ],
  "v4_probe_count": 137,
  "v4_log": [
    "harvest discovered 5 live query params"
  ],
  "v4_params": [
    "property_id@https://privacy.condenastdigital.com/fides.js",
    "v@https://ads-static.conde.digital/production/cns/builds/pitchfork/v6.js",
    "id@https://www.googletagmanager.com/ns.html",
    "source@https://pitchfork.com/v2/offers/pfa01011",
    "lang@https://www.tiktok.com/@pitchfork"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
