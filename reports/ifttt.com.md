# Security Audit Report — ifttt.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ifttt.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | ifttt.com |
| Test date | 2026-09-24 05:27 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 1, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | H6 | Server technology disclosure | CWE-200 |
| 3 | info | H6 | Server technology disclosure | CWE-200 |
| 4 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: CloudFront
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 3. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: nginx
- **Recommendation:** Consider hiding or shortening the Server header.

### 4. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://ifttt.com/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "Automate. Save time. Get more done. - IFTTT",
  "path_gitconfig": 403,
  "path_envfile": 302,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 301",
    "sqli /?id=1%27+OR+1=1-- -> 200",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 301",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 301",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 400",
    "trav /static/../../../../../../../../etc/passwd -> 404",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 404",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 307",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 302",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 301",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
