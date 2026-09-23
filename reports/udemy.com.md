# Security Audit Report — udemy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://udemy.com/ |
| Bug bounty program | [Udemy](https://hackerone.com/udemy) |
| Listed scope domain | udemy.com |
| Test date | 2026-09-23 18:45 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 5, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie __cf_bm lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://www.udemy.com/",
  "https_status": 403,
  "content_type": "text/html; charset=UTF-8",
  "title": "Just a moment...",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 301,
  "path_robots": 301
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
