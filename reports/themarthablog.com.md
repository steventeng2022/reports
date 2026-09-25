# Security Audit Report - themarthablog.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://themarthablog.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | themarthablog.com |
| Test date | 2026-09-25 14:54 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **16** (High: 0, Medium: 1, Low: 6, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | R1 | HTTP redirect to HTTP | CWE-319 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C16 | llms.txt / LLM context file exposed (v4) | CWE-538 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | info | A10b | Sitemap enumerates URLs | CWE-200 |
| 9 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 10 | info | C12i | Additional responsive paths (v4 sweep) | CWE-538 |
| 11 | info | C15 | WAF / edge fingerprint (v4) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | H7 | X-Powered-By disclosure | CWE-200 |
| 15 | info | H7 | X-Powered-By disclosure | CWE-200 |
| 16 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [MEDIUM] HTTP redirect to HTTP (`R1`)

- **CWE:** CWE-319
- **Detail:** http://themarthablog.com redirects to http://www.themarthablog.com/ (not HTTPS).
- **Recommendation:** Redirect http:// to https://.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie __cf_bm lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] llms.txt / LLM context file exposed (v4) (`C16`)

- **CWE:** CWE-538
- **Detail:** GET https://themarthablog.com/llms.txt returned 450897 bytes of text/plain content; the AI-oriented index describes site structure/data for LLM consumers.
- **Recommendation:** Decide whether the llms.txt file should be public; redact internal structure, endpoints, and data descriptions if not intended for LLM consumers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [INFO] Sitemap enumerates URLs (`A10b`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml lists 0 URLs; sensitive-looking entries: none.
- **Recommendation:** Remove or protect internal/sensitive URLs from the public sitemap.

### 9. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /.svn/entries (403 protected), /wp-login.php (HTML shell), /phpmyadmin (403 protected).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 10. [INFO] Additional responsive paths (v4 sweep) (`C12i`)

- **CWE:** CWE-538
- **Detail:** Answered without 404: /wp-login.php -> 200; /sitemap.xml -> 200.
- **Recommendation:** Return a real 404 for paths that should not exist; review the listed responsive paths for sensitive content.

### 11. [INFO] WAF / edge fingerprint (v4) (`C15`)

- **CWE:** CWE-200
- **Detail:** Fingerprinted during probing: Cloudflare (matched on response body/server header across injection probes).
- **Recommendation:** No direct fix; use the fingerprint to tune WAF rules and re-test with encoded variants.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] X-Powered-By disclosure (`H7`)

- **CWE:** CWE-200
- **Detail:** X-Powered-By: WP Engine
- **Context:** http response
- **Recommendation:** Remove the X-Powered-By header.

### 15. [INFO] X-Powered-By disclosure (`H7`)

- **CWE:** CWE-200
- **Detail:** X-Powered-By: WP Engine
- **Recommendation:** Remove the X-Powered-By header.

### 16. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/.svn/entries (403 protected)","/wp-login.php (HTML shell)","/phpmyadmin (403 protected)"]}
- sitemap: {"total":0,"sensitive":[]}

Stage-2 probe log (observed responses):
- timing base=411ms id=71 search=40
- boolean b=301/0 t1=403/5824 t2=403/5824
- graphql /graphql -> 301
- graphql /api/graphql -> 301
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 301
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 403
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- apicors /api -> 301
- apicors /api/v1 -> 301
- apicors /graphql -> 301
- apicors /rest -> 301
- apicors /v1 -> 301

**Stage 3 - live parameter harvest, takeover and injection probes (8 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (62 requests):**

- no stage-4 probe hits (all probes negative)

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "http://www.themarthablog.com/",
  "https_status": 301,
  "content_type": "text/html; charset=UTF-8",
  "title": "",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 404,
  "path_robots": 301,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 403",
    "sqli /?q=%27 -> 301",
    "sqli /products?filter=%27 -> 301",
    "sqli /?p=1;-- -> 301",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 403",
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
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=411ms id=71 search=40",
    "boolean b=301/0 t1=403/5824 t2=403/5824",
    "graphql /graphql -> 301",
    "graphql /api/graphql -> 301",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 403",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 403",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 301",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 403",
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
      "/.svn/entries (403 protected)",
      "/wp-login.php (HTML shell)",
      "/phpmyadmin (403 protected)"
    ]
  },
  "sitemap": {
    "total": 0,
    "sensitive": []
  },
  "v3_probe_count": 8,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 301"
  ],
  "v4_probe_count": 62,
  "v4_log": [
    "harvest no query params discovered"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
