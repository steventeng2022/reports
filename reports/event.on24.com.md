# Security Audit Report — event.on24.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://event.on24.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | event.on24.com |
| Test date | 2026-09-24 05:27 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 3, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | R2 | No HTTP->HTTPS redirect | CWE-319 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | I10 | Unusual 418 status on HTTPS root | CWE-703 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie BIGipServereventprd_apache lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] No HTTP->HTTPS redirect (`R2`)

- **CWE:** CWE-319
- **Detail:** http://event.on24.com/ returns 403 (Apache) without redirecting to HTTPS; an HSTS header (max-age=31536000; includeSubDomains) is present, so browsers upgrade after first visit. Note: the HTTPS root answers 418 (I am a teapot), an unusual status for a live service.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Apache
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Unusual 418 status on HTTPS root (`I10`)

- **CWE:** CWE-703
- **Detail:** GET https://event.on24.com/ returns 418 I Am a Teapot (with HSTS preload) while the HTTP root returns 403; the service responds, but the non-standard status suggests a dormant or bot-walled endpoint.
- **Recommendation:** Review and remediate per CWE guidance.

## Evidence (raw response observations)

```json
{
  "http_status": 403,
  "https_status": 418,
  "content_type": "text/html; charset=utf-8",
  "title": "Access Restricted",
  "path_gitconfig": 418,
  "path_envfile": 418,
  "path_securitytxt": 418,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 418",
    "sqli /?id=1%27+OR+1=1-- -> 418",
    "sqli /?q=%27 -> 418",
    "sqli /products?filter=%27 -> 302",
    "sqli /?p=1;-- -> 418",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 418",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 418",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 418",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 418",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 418",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 418",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 418",
    "trav /static/../../../../../../../../etc/passwd -> 418",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 418",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 418",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 418",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 418",
    "host no reflection -> 418",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 418",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 418"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
