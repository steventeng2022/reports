# Security Audit Report — blogs.windows.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blogs.windows.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | blogs.windows.com |
| Test date | 2026-09-24 03:59 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 2, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | I9 | HTTP/HTTPS redirect loop on legacy post URLs | CWE-319 |
| 3 | info | H6 | Server technology disclosure | CWE-200 |
| 4 | info | H6 | Server technology disclosure | CWE-200 |
| 5 | info | H7 | X-Powered-By disclosure | CWE-200 |
| 6 | info | I5 | Open redirect candidate refuted (/go matches a 2013 blog post) | CWE-601 |
| 7 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie __cf_bm lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] HTTP/HTTPS redirect loop on legacy post URLs (`I9`)

- **CWE:** CWE-319
- **Detail:** The 2013 post /bloggingwindows/2013-09-12/go-behind-the-scenes... 301s https->http, and the http copy 301s back to https, forming an infinite redirect loop for bookmarked legacy URLs (confirmed with and without query parameters).
- **Recommendation:** Review and remediate per CWE guidance.

### 3. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 4. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

### 5. [INFO] X-Powered-By disclosure (`H7`)

- **CWE:** CWE-200
- **Detail:** X-Powered-By: WP Engine
- **Recommendation:** Remove the X-Powered-By header.

### 6. [INFO] Open redirect candidate refuted (/go matches a 2013 blog post) (`I5`)

- **CWE:** CWE-601
- **Detail:** https://blogs.windows.com/go?url=301s to a 2013 blog post URL (go-behind-the-scenes-of-the-recital) keeping the parameter; the post never redirects to it.
- **Recommendation:** Review and remediate per CWE guidance.

### 7. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://blogs.windows.com/",
  "https_status": 200,
  "content_type": "text/html; charset=UTF-8",
  "title": "Home | Windows Blog",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 26,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 403",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 404",
    "sqli /?p=1;-- -> 404",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 403",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 403",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 404",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 404",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 403",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 301",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 301",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 301"
  ],
  "open_redirect": {
    "path": "/go?url=https%3A%2F%2Fevil-cors.example%2Fx",
    "location": "http://blogs.windows.com/bloggingwindows/2013/09/12/go-behind-the-scenes-of-the-recital-our-popular-windows-phone-ad/?url=https%3A%2F%2Fevil-cors.example%2Fx"
  }
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
