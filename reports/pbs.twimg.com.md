# Security Audit Report — pbs.twimg.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pbs.twimg.com/ |
| Bug bounty program | [Twitter](https://hackerone.com/twitter) |
| Listed scope domain | twimg.com |
| Test date | 2026-09-23 19:25 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 6, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | R2 | No HTTP->HTTPS redirect on CDN root (expected 400) | CWE-319 |
| 6 | low | X2 | CORS origin reflection without credentials (400 error response) | CWE-942 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [LOW] No HTTP->HTTPS redirect on CDN root (expected 400) (`R2`)

- **CWE:** CWE-319
- **Detail:** Verified: http://pbs.twimg.com/ returns 400 with no Location header. pbs.twimg.com is the X/Twitter media CDN which serves media by path; a 400 on the bare root is expected CDN behavior rather than a misconfiguration. HSTS (max-age=631138519; includeSubdomains) is present on the plain-HTTP response, mitigating downgrade risk.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

### 6. [LOW] CORS origin reflection without credentials (400 error response) (`X2`)

- **CWE:** CWE-942
- **Detail:** Verified: GET https://pbs.twimg.com/ with Origin: https://evil.example returns 400 with access-control-allow-origin: https://evil.example but WITHOUT access-control-allow-credentials. The response is an error response with empty body and no content-type; without credentials the reflected origin cannot directly leak sensitive data. The CDN reflects arbitrary origins on the root error response.
- **Recommendation:** Echo the Origin only after validating against an allow-list; avoid reflecting untrusted origins.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "http_status": 400,
  "https_status": 400,
  "content_type": "",
  "title": "",
  "path_gitconfig": 404,
  "path_envfile": 400,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
