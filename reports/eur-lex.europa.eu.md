# Security Audit Report — eur-lex.europa.eu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eur-lex.europa.eu/ |
| Bug bounty program | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| Listed scope domain | europa.eu |
| Test date | 2026-09-24 00:54 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 14, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookie without Secure flag | CWE-614 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C1 | Cookie without Secure flag | CWE-614 |
| 4 | low | C1 | Cookie without Secure flag | CWE-614 |
| 5 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 6 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 7 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 8 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 9 | low | H1 | Missing HSTS header | CWE-319 |
| 10 | low | H2 | Missing CSP header | CWE-1021 |
| 11 | low | H2 | Missing CSP header | CWE-1021 |
| 12 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 13 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 14 | low | H4 | No clickjacking protection | CWE-1023 |
| 15 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 16 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 17 | info | H6 | Server technology disclosure | CWE-200 |
| 18 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie AWSALB lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie AWSALBCORS lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie experimentalFeaturesActivated lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 4. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie dtCookie lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 5. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie AWSALB lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 6. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie AWSALBCORS lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 7. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie experimentalFeaturesActivated lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 8. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie dtCookie lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 9. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 10. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 11. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 12. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 13. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 14. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 15. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 16. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 17. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: CloudFront
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 18. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://eur-lex.europa.eu/",
  "https_status": 200,
  "content_type": "text/html; charset=UTF-8",
  "title": "EUR-Lex — Access to European Union law — choose your language",
  "path_gitconfig": 404,
  "path_envfile": 403,
  "path_securitytxt": 404,
  "path_robots": 200,
  "robots_found": true
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
