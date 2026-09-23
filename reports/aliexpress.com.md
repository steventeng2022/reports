# Security Audit Report — aliexpress.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aliexpress.com/ |
| Bug bounty program | [Alibaba](https://hackerone.com/alibaba) |
| Listed scope domain | aliexpress.com |
| Test date | 2026-09-23 19:02 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **16** (High: 0, Medium: 1, Low: 10, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | X2 | CORS origin reflection with credentials | CWE-942 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | low | H4 | No clickjacking protection | CWE-1023 |
| 11 | low | H4 | No clickjacking protection | CWE-1023 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |
| 16 | info | P1 | SPA fallback 200 on /.git/config (no git data exposed) | CWE-1038 |

## Detailed findings

### 1. [MEDIUM] CORS origin reflection with credentials (`X2`)

- **CWE:** CWE-942
- **Detail:** Verified: GET https://aliexpress.com/ with Origin: https://evil.example returns 200 with access-control-allow-origin: https://evil.example AND access-control-allow-credentials: true. The page itself is public; impact on authenticated/JSON endpoints should be validated during triage.
- **Recommendation:** Echo the Origin only after validating against an allow-list; avoid reflecting untrusted origins.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie x5secdata lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie x5secdata lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 10. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 11. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Tengine/AServer-Ingress
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 15. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Tengine/AServer-Ingress
- **Recommendation:** Consider hiding or shortening the Server header.

### 16. [INFO] SPA fallback 200 on /.git/config (no git data exposed) (`P1`)

- **CWE:** CWE-1038
- **Detail:** Verified: GET https://aliexpress.com/.git/config returns 200 (text/html via Tengine); body is the application HTML fallback, not git metadata. Informational.
- **Recommendation:** Review and remediate per CWE guidance.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://aliexpress.com/",
  "https_status": 200,
  "content_type": "text/html;charset=UTF-8",
  "title": "",
  "path_gitconfig": 200,
  "path_envfile": 301,
  "path_securitytxt": 301,
  "path_robots": 301
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
