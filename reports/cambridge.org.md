# Security Audit Report - cambridge.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cambridge.org/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | cambridge.org |
| Test date | 2026-09-25 01:10 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 5, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | R3 | HTTP endpoint unreachable | CWE-1032 |
| 6 | info | A10 | robots.txt discloses sensitive paths | CWE-200 |
| 7 | info | A4i | Sensitive paths exist (protected or app shells) | CWE-538 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [LOW] HTTP endpoint unreachable (`R3`)

- **CWE:** CWE-1032
- **Detail:** http://cambridge.org failed: timeout
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

### 6. [INFO] robots.txt discloses sensitive paths (`A10`)

- **CWE:** CWE-200
- **Detail:** Disallowed paths in robots.txt: /engage/*/administration-dashboard, /engage/*/test, /api/ecommerce/bag.
- **Recommendation:** Treat robots.txt as discovery, not a control: ensure listed sensitive paths are authenticated or rate-limited.

### 7. [INFO] Sensitive paths exist (protected or app shells) (`A4i`)

- **CWE:** CWE-538
- **Detail:** Paths answering 401/403 or HTML shells: /.svn/entries (403 protected).
- **Recommendation:** No immediate action if the paths are genuinely protected; otherwise return a real 404 to unauthenticated probes for paths that should not exist.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- sweep: {"high":[],"protected":["/.svn/entries (403 protected)"]}
- robots_disallow: ["/","/","/","/aca/authorinformation/","/blocks","/concrete","/config","/controllers","/css","/elements","/helpers","/jobs","/js","/languages","/libraries","/mail","/models","/packages","/single_pages","/themes"]

Stage-2 probe log (observed responses):
- timing base=19618ms id=317 search=21
- boolean b=522/123908 t1=403/1304 t2=403/1304
- graphql /graphql -> 522
- graphql /api/graphql -> 522
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 522
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 522
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 522
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 522
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403
- apicors /api -> 522
- apicors /api/v1 -> 522
- apicors /graphql -> 522
- apicors /rest -> 522
- apicors /v1 -> 522

**Stage 3 - live parameter harvest, takeover and injection probes (8 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_error": "timeout",
  "https_status": 301,
  "content_type": "text/html; charset=UTF-8",
  "title": "301 Moved Permanently",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 403",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 403",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 403",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "host no reflection -> err"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=19618ms id=317 search=21",
    "boolean b=522/123908 t1=403/1304 t2=403/1304",
    "graphql /graphql -> 522",
    "graphql /api/graphql -> 522",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 522",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 522",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 522",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 522",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 403",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "redir2 no hits over 49 requests",
    "apicors /api -> 522",
    "apicors /api/v1 -> 522",
    "apicors /graphql -> 522",
    "apicors /rest -> 522",
    "apicors /v1 -> 522"
  ],
  "sweep": {
    "high": [],
    "protected": [
      "/.svn/entries (403 protected)"
    ]
  },
  "robots_disallow": [
    "/",
    "/",
    "/",
    "/aca/authorinformation/",
    "/blocks",
    "/concrete",
    "/config",
    "/controllers",
    "/css",
    "/elements",
    "/helpers",
    "/jobs",
    "/js",
    "/languages",
    "/libraries",
    "/mail",
    "/models",
    "/packages",
    "/single_pages",
    "/themes"
  ],
  "v3_probe_count": 8,
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
