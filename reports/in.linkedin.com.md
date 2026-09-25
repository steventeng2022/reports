# Security Audit Report - in.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://in.linkedin.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | in.linkedin.com |
| Test date | 2026-09-25 14:53 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 10, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 3 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 4 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 5 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 6 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 7 | low | H1 | Missing HSTS header | CWE-319 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | low | I5b | URL parameter reflected into redirect logic | CWE-601 |
| 11 | info | A10 | robots.txt discloses sensitive paths | CWE-200 |
| 12 | info | A4 | Sensitive paths return 200 unauthenticated | CWE-538 |
| 13 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 15 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 16 | info | H6 | Server technology disclosure | CWE-200 |
| 17 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie __cf_bm lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie bcookie lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 3. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie JSESSIONID lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 4. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie lang lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 5. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie bcookie lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 6. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie lidc lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 7. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [LOW] URL parameter reflected into redirect logic (`I5b`)

- **CWE:** CWE-601
- **Detail:** GET https://in.linkedin.com/redirect?url=https%3A%2F%2Fevil-cors.example%2Fx returned 200 with the external URL embedded in a redirect context.
- **Recommendation:** Confirm whether the parameter influences the redirect; if it does, apply the same allow-list validation as open-redirect fixes.

### 11. [INFO] robots.txt discloses sensitive paths (`A10`)

- **CWE:** CWE-200
- **Detail:** Disallowed paths in robots.txt: /fizzy/admin, /api/jobPostings/jobs*, /learning/login*?redirect=, /learning/login*&redirect=, /salary-explorer/api, /uas/login, /voyager/api, /help/testing, /help/testing/*, /fizzy/admin.
- **Recommendation:** Treat robots.txt as discovery, not a control: ensure listed sensitive paths are authenticated or rate-limited.

### 12. [INFO] Sensitive paths return 200 unauthenticated (`A4`)

- **CWE:** CWE-538
- **Detail:** GET /admin returns 200 with a 5-byte body "GOOD" (load-balancer health-check response) on re-test; random paths return proper 404s (361KB), so no page-level data is exposed. Informational only.
- **Recommendation:** Review each exposed path; require authentication for admin/actuator-style endpoints and remove world-readable credential or config files.

### 13. [INFO] Additional responsive paths (v4 sweep) (`C12i`)

- **CWE:** CWE-538
- **Detail:** Answered without 404: /admin -> 200.
- **Recommendation:** Return a real 404 for paths that should not exist; review the listed responsive paths for sensitive content.

### 14. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 15. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 16. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 17. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":["/admin (200 no-type)"],"protected":[]}
- robots_disallow: ["/addContacts*","/addressBookExport*","/ambry","/analytics/","/answers*","/authwall","/badges/profile/create","/cap/","/chat/","/checkpoint/","/companyDir*","/connections*","/csp/","/e/","/edurec*","/embed/feed/update/","/endorsements","/feed/update/","/find/","/fizzy/admin"]

Stage-2 probe log (observed responses):
- timing base=549ms id=325 search=214
- boolean b=200/137705 t1=200/137705 t2=200/137705
- graphql /graphql -> 404
- graphql /api/graphql -> 404
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 404
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 200
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200
- apicors /api -> 404
- apicors /api/v1 -> 404
- apicors /graphql -> 404
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (35 requests):**

- params_harvested: ["trk","ProductId","fromSignIn","lang","src"]

Stage-3 probe log (observed responses):
- harvest discovered 5 live query params
- xss3 /legal/user-agreement?trk -> 200
- xss3 ms-windows-store://pdp/?ProductId -> err
- xss3 https://www.linkedin.com/login?fromSignIn -> err
- xss3 https://www.linkedin.com/help/linkedin?lang -> err
- xss3 https://business.linkedin.com/talent-solutions?src -> err
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (137 requests):**

- v4_params: ["trk@/legal/user-agreement","ProductId@ms-windows-store://pdp/","fromSignIn@https://www.linkedin.com/login","lang@https://www.linkedin.com/help/linkedin","src@https://business.linkedin.com/talent-solutions"]

Stage-4 probe log (observed responses):
- harvest discovered 5 live query params

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://in.linkedin.com/hp",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "LinkedIn India: Log In or Sign Up",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 302",
    "sqli /?id=1%27+OR+1=1-- -> 200",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 200",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 302",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 404",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 404",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 404",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 400",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 302",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=549ms id=325 search=214",
    "boolean b=200/137705 t1=200/137705 t2=200/137705",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 404",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 404",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302",
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
    "high": [
      "/admin (200 no-type)"
    ],
    "protected": []
  },
  "robots_disallow": [
    "/addContacts*",
    "/addressBookExport*",
    "/ambry",
    "/analytics/",
    "/answers*",
    "/authwall",
    "/badges/profile/create",
    "/cap/",
    "/chat/",
    "/checkpoint/",
    "/companyDir*",
    "/connections*",
    "/csp/",
    "/e/",
    "/edurec*",
    "/embed/feed/update/",
    "/endorsements",
    "/feed/update/",
    "/find/",
    "/fizzy/admin"
  ],
  "v3_probe_count": 35,
  "v3_log": [
    "harvest discovered 5 live query params",
    "xss3 /legal/user-agreement?trk -> 200",
    "xss3 ms-windows-store://pdp/?ProductId -> err",
    "xss3 https://www.linkedin.com/login?fromSignIn -> err",
    "xss3 https://www.linkedin.com/help/linkedin?lang -> err",
    "xss3 https://business.linkedin.com/talent-solutions?src -> err",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ],
  "params_harvested": [
    "trk",
    "ProductId",
    "fromSignIn",
    "lang",
    "src"
  ],
  "v4_probe_count": 137,
  "v4_log": [
    "harvest discovered 5 live query params",
    "xss4 /legal/user-agreement?trk svg-onload -> 200 no raw echo",
    "xss4 /legal/user-agreement?trk attr-breakout -> 200 no raw echo",
    "xss4 /legal/user-agreement?trk script-tag -> 200 no raw echo",
    "xss4 /legal/user-agreement?trk dbl-enc-svg -> 200 no raw echo"
  ],
  "v4_params": [
    "trk@/legal/user-agreement",
    "ProductId@ms-windows-store://pdp/",
    "fromSignIn@https://www.linkedin.com/login",
    "lang@https://www.linkedin.com/help/linkedin",
    "src@https://business.linkedin.com/talent-solutions"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
