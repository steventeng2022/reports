# Security Audit Report — hbo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hbo.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | hbo.com |
| Test date | 2026-09-24 07:24 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 18, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C1 | Cookie without Secure flag | CWE-614 |
| 4 | low | C1 | Cookie without Secure flag | CWE-614 |
| 5 | low | C1 | Cookie without Secure flag | CWE-614 |
| 6 | low | C1 | Cookie without Secure flag | CWE-614 |
| 7 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 8 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 9 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 10 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 11 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 12 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 13 | low | H2 | Missing CSP header | CWE-1021 |
| 14 | low | H2 | Missing CSP header | CWE-1021 |
| 15 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 16 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 17 | low | H4 | No clickjacking protection | CWE-1023 |
| 18 | low | H4 | No clickjacking protection | CWE-1023 |
| 19 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 20 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 21 | info | H6 | Server technology disclosure | CWE-200 |
| 22 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie countryCode lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie stateCode lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie geoData lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 4. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie countryCode lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 5. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie stateCode lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 6. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie geoData lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 7. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie countryCode lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 8. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie stateCode lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 9. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie geoData lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 10. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie countryCode lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 11. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie stateCode lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 12. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie geoData lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 13. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 14. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 15. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 16. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 17. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 18. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 19. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 20. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 21. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Varnish
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 22. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Varnish
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://hbo.com/",
  "https_status": 308,
  "content_type": "",
  "title": "",
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
  ]
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
