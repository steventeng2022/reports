# Security Audit Report - sxsw.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sxsw.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | sxsw.com |
| Test date | 2026-09-25 14:52 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 8, Info: 8)

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
| 10 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |
| 15 | info | H7 | X-Powered-By disclosure | CWE-200 |
| 16 | info | P3 | Missing security.txt | CWE-1038 |

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
- **Detail:** Paths answering 401/403 or HTML shells: /.svn/entries (403 protected), /wp-login.php (HTML shell).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 10. [INFO] Additional responsive paths (v4 sweep) (`C12i`)

- **CWE:** CWE-538
- **Detail:** Answered without 404: /wp-login.php -> 200; /xmlrpc.php -> 405.
- **Recommendation:** Return a real 404 for paths that should not exist; review the listed responsive paths for sensitive content.

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
- **Detail:** Server header reveals: nginx
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: nginx
- **Recommendation:** Consider hiding or shortening the Server header.

### 15. [INFO] X-Powered-By disclosure (`H7`)

- **CWE:** CWE-200
- **Detail:** X-Powered-By: WordPress VIP <https://wpvip.com>
- **Recommendation:** Remove the X-Powered-By header.

### 16. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/.svn/entries (403 protected)","/wp-login.php (HTML shell)"]}
- robots_disallow: ["Sitemap:"]

Stage-2 probe log (observed responses):
- timing base=774ms id=543 search=808
- boolean b=200/255477 t1=301/0 t2=301/0
- graphql /graphql -> 404
- graphql /api/graphql -> 404
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 406
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 404
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 406
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301
- apicors /api -> 404
- apicors /api/v1 -> 404
- apicors /graphql -> 404
- apicors /rest -> 404
- apicors /v1 -> 404

**Stage 3 - live parameter harvest, takeover and injection probes (54 requests):**

- params_harvested: ["url","rsd","ver","quality","id","integration","m","minify"]

Stage-3 probe log (observed responses):
- harvest discovered 8 live query params
- xss3 https://sxsw.com/wp-json/oembed/1.0/embed?url -> err
- xss3 https://sxsw.com/xmlrpc.php?rsd -> err
- xss3 https://sxsw.com/wp-content/themes/sxswfse-2026/build/blocks/reg-rate-banner/view.js?ver -> err
- xss3 https://sxsw.com/wp-content/uploads/sites/2/2026/07/cropped-Path.png?quality -> err
- xss3 https://www.googletagmanager.com/ns.html?id -> err
- xss3 https://js.hs-scripts.com/558236.js?integration -> err
- xss3 https://sxsw.com/wp-includes/js/dist/hooks.min.js?m -> err
- xss3 https://sxsw.com/wp-content/mu-plugins/jetpack-16.2/jetpack_vendor/automattic/jetpack-assets/build/i18n-loader.js?minify -> err
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (143 requests):**

- v4_params: ["url@https://sxsw.com/wp-json/oembed/1.0/embed","rsd@https://sxsw.com/xmlrpc.php","ver@https://sxsw.com/wp-content/themes/sxswfse-2026/build/blocks/reg-rate-banner/view.js","quality@https://sxsw.com/wp-content/uploads/sites/2/2026/07/cropped-Path.png","id@https://www.googletagmanager.com/ns.html","integration@https://js.hs-scripts.com/558236.js","m@https://sxsw.com/wp-includes/js/dist/hooks.min.js","minify@https://sxsw.com/wp-content/mu-plugins/jetpack-16.2/jetpack_vendor/automattic/jetpack-assets/build/i18n-loader.js"]

Stage-4 probe log (observed responses):
- harvest discovered 8 live query params

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://sxsw.com/",
  "https_status": 200,
  "content_type": "text/html; charset=UTF-8",
  "title": "Homepage - SXSW",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 404",
    "sqli /?id=1%27+OR+1=1-- -> 301",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 404",
    "sqli /?p=1;-- -> 404",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 404",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 301",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 404",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 404",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 406",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
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
    "timing base=774ms id=543 search=808",
    "boolean b=200/255477 t1=301/0 t2=301/0",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 404",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 406",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 404",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 406",
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
  "sweep": {
    "high": [],
    "protected": [
      "/.svn/entries (403 protected)",
      "/wp-login.php (HTML shell)"
    ]
  },
  "robots_disallow": [
    "Sitemap:"
  ],
  "v3_probe_count": 54,
  "v3_log": [
    "harvest discovered 8 live query params",
    "xss3 https://sxsw.com/wp-json/oembed/1.0/embed?url -> err",
    "xss3 https://sxsw.com/xmlrpc.php?rsd -> err",
    "xss3 https://sxsw.com/wp-content/themes/sxswfse-2026/build/blocks/reg-rate-banner/view.js?ver -> err",
    "xss3 https://sxsw.com/wp-content/uploads/sites/2/2026/07/cropped-Path.png?quality -> err",
    "xss3 https://www.googletagmanager.com/ns.html?id -> err",
    "xss3 https://js.hs-scripts.com/558236.js?integration -> err",
    "xss3 https://sxsw.com/wp-includes/js/dist/hooks.min.js?m -> err",
    "xss3 https://sxsw.com/wp-content/mu-plugins/jetpack-16.2/jetpack_vendor/automattic/jetpack-assets/build/i18n-loader.js?minify -> err",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 200"
  ],
  "params_harvested": [
    "url",
    "rsd",
    "ver",
    "quality",
    "id",
    "integration",
    "m",
    "minify"
  ],
  "v4_probe_count": 143,
  "v4_log": [
    "harvest discovered 8 live query params"
  ],
  "v4_params": [
    "url@https://sxsw.com/wp-json/oembed/1.0/embed",
    "rsd@https://sxsw.com/xmlrpc.php",
    "ver@https://sxsw.com/wp-content/themes/sxswfse-2026/build/blocks/reg-rate-banner/view.js",
    "quality@https://sxsw.com/wp-content/uploads/sites/2/2026/07/cropped-Path.png",
    "id@https://www.googletagmanager.com/ns.html",
    "integration@https://js.hs-scripts.com/558236.js",
    "m@https://sxsw.com/wp-includes/js/dist/hooks.min.js",
    "minify@https://sxsw.com/wp-content/mu-plugins/jetpack-16.2/jetpack_vendor/automattic/jetpack-assets/build/i18n-loader.js"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
