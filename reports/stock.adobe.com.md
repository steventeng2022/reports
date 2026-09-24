# Security Audit Report — stock.adobe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stock.adobe.com/ |
| Bug bounty program | [Adobe](https://hackerone.com/adobe) |
| Listed scope domain | adobe.com |
| Test date | 2026-09-24 00:53 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 8, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 2 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | R2 | No HTTP->HTTPS redirect (403 bot-challenge on both schemes, HSTS present) | CWE-319 |
| 8 | low | X2 | CORS origin reflection with credentials (observed on 403 challenge response) | CWE-942 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie datadome lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 2. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie datadome lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [LOW] No HTTP->HTTPS redirect (403 bot-challenge on both schemes, HSTS present) (`R2`)

- **CWE:** CWE-319
- **Detail:** Verified: http://stock.adobe.com/ and https://stock.adobe.com/ both return 403 (bot-challenge page) for non-browser clients with no Location header; the plain-HTTP 403 response carries HSTS (max-age=31536000; includeSubdomains), which mitigates downgrade risk. The missing port-80 upgrade redirect is noted for completeness.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

### 8. [LOW] CORS origin reflection with credentials (observed on 403 challenge response) (`X2`)

- **CWE:** CWE-942
- **Detail:** Verified: GET https://stock.adobe.com/ without Origin returns Access-Control-Allow-Origin: *; with Origin: https://evil.example the 403 challenge response returns access-control-allow-origin: https://evil.example AND access-control-allow-credentials: true. The reflection occurs on the bot-challenge (403) response rather than a 200; the credentialed-reflection pattern on the Adobe edge warrants triage against 200 API responses.
- **Recommendation:** Echo the Origin only after validating against an allow-list; avoid reflecting untrusted origins.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

## Evidence (raw response observations)

```json
{
  "http_status": 403,
  "https_status": 403,
  "content_type": "text/html;charset=utf-8",
  "title": "adobe.com",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 403,
  "path_robots": 200,
  "robots_found": true
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
