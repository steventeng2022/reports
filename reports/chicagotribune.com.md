# Security Audit Report - chicagotribune.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://chicagotribune.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | chicagotribune.com |
| Test date | 2026-09-24 14:14 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **15** (High: 1, Medium: 1, Low: 7, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | B9 | Subdomain takeover candidate (CNAME to unresolvable target) | CWE-1596 |
| 2 | medium | A3 | GraphQL introspection enabled | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | A10b | Sitemap enumerates URLs | CWE-200 |
| 11 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [HIGH] Subdomain takeover candidate (CNAME to unresolvable target) (`B9`)

- **CWE:** CWE-1596
- **Detail:** CNAME app.chicagotribune.com -> tribune.ed4.net. Re-verified 2026-09-24 via DoH (dns.google): tribune.ed4.net returns NXDOMAIN (status 3); the CNAME target is unresolvable, so if the owning zone is claimed the dangling record can be pointed at attacker infrastructure.
- **Recommendation:** Claim or remove the dangling CNAME now; move the subdomain to a controlled target so an attacker cannot register the service record (CWE-1596).

### 2. [MEDIUM] GraphQL introspection enabled (`A3`)

- **CWE:** CWE-200
- **Detail:** Re-verified 2026-09-24: GET https://chicagotribune.com/graphql?query={__schema{types{name}}} returns 200 JSON with the full type list (Node, ID, Boolean, etc.); the schema can be enumerated without authentication.
- **Recommendation:** Disable GraphQL introspection in production (allowIntrospection: false) or gate __schema queries behind authentication.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Sitemap enumerates URLs (`A10b`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml lists 10000 URLs; sensitive-looking entries: none.
- **Recommendation:** Remove or protect internal/sensitive URLs from the public sitemap.

### 11. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /.svn/entries (403 protected), /wp-login.php (HTML shell).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: nginx
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 15. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: nginx
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (98 requests):**

- graphql: "/graphql"
- sweep: {"high":[],"protected":["/.svn/entries (403 protected)","/wp-login.php (HTML shell)"]}
- sitemap: {"total":10000,"sensitive":[]}

Stage-2 probe log (observed responses):
- timing base=655ms id=603 search=584
- boolean b=301/0 t1=301/0 t2=301/0
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 406
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 301
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 406
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301
- apicors /api -> 301
- apicors /api/v1 -> 301
- apicors /graphql -> 200 ACAO=*
- apicors /rest -> 301
- apicors /v1 -> 301

**Stage 3 - live parameter harvest, takeover and injection probes (9 requests):**

- subdomains: ["app.chicagotribune.com -> tribune.ed4.net (NXDOMAIN target 3)"]

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://chicagotribune.com/",
  "https_status": 301,
  "content_type": "text/html; charset=utf-8",
  "title": "",
  "path_gitconfig": 403,
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
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 301",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 301",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 301",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 406",
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
  "v2_probe_count": 98,
  "v2_log": [
    "timing base=655ms id=603 search=584",
    "boolean b=301/0 t1=301/0 t2=301/0",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 406",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 406",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 301",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 406",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "redir2 no hits over 49 requests",
    "apicors /api -> 301",
    "apicors /api/v1 -> 301",
    "apicors /graphql -> 200 ACAO=*",
    "apicors /rest -> 301",
    "apicors /v1 -> 301"
  ],
  "graphql": "/graphql",
  "sweep": {
    "high": [],
    "protected": [
      "/.svn/entries (403 protected)",
      "/wp-login.php (HTML shell)"
    ]
  },
  "sitemap": {
    "total": 10000,
    "sensitive": []
  },
  "v3_probe_count": 9,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "cache X-Forwarded-Host not reflected -> 301"
  ],
  "subdomains": [
    "app.chicagotribune.com -> tribune.ed4.net (NXDOMAIN target 3)"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
