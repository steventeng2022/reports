# Security Audit Report — github.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://github.com/ |
| Bug bounty program | [GitHub](https://hackerone.com/github) |
| Listed scope domain | github.com |
| Test date | 2026-09-23 20:01 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 5, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie _octo lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: github.com
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://github.com/",
  "https_status": 200,
  "content_type": "text/html; charset=utf-8",
  "title": "GitHub · Change is constant. GitHub keeps you ahead. · GitHub",
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
