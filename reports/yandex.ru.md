# Security Audit Report — yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yandex.ru/ |
| Bug bounty program | [Yandex](https://yandex.com/bugbounty/index) |
| Listed scope domain | yandex.ru |
| Test date | 2026-09-23 20:59 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 21, Info: 2)

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
| 13 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 14 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 15 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 16 | low | H1 | Missing HSTS header | CWE-319 |
| 17 | low | H1 | Missing HSTS header | CWE-319 |
| 18 | low | H2 | Missing CSP header | CWE-1021 |
| 19 | low | H2 | Missing CSP header | CWE-1021 |
| 20 | low | H4 | No clickjacking protection | CWE-1023 |
| 21 | low | H4 | No clickjacking protection | CWE-1023 |
| 22 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 23 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie is_gdpr lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie is_gdpr_b lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie bh lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 4. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie is_gdpr lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 5. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie is_gdpr_b lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 6. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie bh lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 7. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie is_gdpr lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 8. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie is_gdpr_b lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 9. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie _yasc lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 10. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie bh lacks HttpOnly; readable by client-side JS.
- **Context:** http response
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 11. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie is_gdpr lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 12. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie is_gdpr_b lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 13. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie _yasc lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 14. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie yandexuid lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 15. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie bh lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 16. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 17. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 18. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 19. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 20. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 21. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 22. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 23. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://yandex.ru/",
  "https_status": 302,
  "content_type": "",
  "title": "",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 200,
  "robots_found": true
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
