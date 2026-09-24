# Security Audit Report — eventim.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eventim.de/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | eventim.de |
| Test date | 2026-09-24 04:00 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 1, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | R3 | HTTP endpoint unreachable | CWE-1032 |

## Detailed findings

### 1. [LOW] HTTP endpoint unreachable (`R3`)

- **CWE:** CWE-1032
- **Detail:** http://eventim.de failed: read ECONNRESET
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

## Evidence (raw response observations)

```json
{
  "http_error": "read ECONNRESET",
  "https_error": "read ECONNRESET",
  "path_envfile": 403,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 403,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 403",
    "sqli /?id=1%27+OR+1=1-- -> 403",
    "sqli /?q=%27 -> 403",
    "sqli /products?filter=%27 -> 403",
    "sqli /?p=1;-- -> 403",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 403",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 403",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 403",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 403",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 403",
    "trav /static/../../../../../../../../etc/passwd -> 403",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 403",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 403",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 403",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 403",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 403",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 403"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
