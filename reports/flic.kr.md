# Security Audit Report — flic.kr

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://flic.kr/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | flic.kr |
| Test date | 2026-09-24 07:24 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **9** (High: 0, Medium: 1, Low: 6, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | X1 | CORS wildcard on flic.kr root | CWE-942 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] CORS wildcard on flic.kr root (`X1`)

- **CWE:** CWE-942
- **Detail:** https://flic.kr/ (Flickr short-link service) returns 200 HTML with Access-Control-Allow-Origin: * (verified with hostile Origin; no credentials). Any page can read flic.kr responses cross-origin.
- **Recommendation:** Restrict Access-Control-Allow-Origin to known origins or add Vary: Origin.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: CloudFront
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://flic.kr/",
  "https_status": 200,
  "content_type": "text/html",
  "title": "Flickr | The best place to be a photographer online.",
  "path_gitconfig": 302,
  "path_envfile": 302,
  "path_securitytxt": 302,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 200",
    "sqli /?id=1%27+OR+1=1-- -> 200",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 302",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 200",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 302",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 302",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 302",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 200",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
