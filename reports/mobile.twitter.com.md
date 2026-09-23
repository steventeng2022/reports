# Security Audit Report — mobile.twitter.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mobile.twitter.com/ |
| Bug bounty program | [Twitter](https://hackerone.com/twitter) |
| Listed scope domain | twitter.com |
| Test date | 2026-09-23 20:00 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **16** (High: 0, Medium: 1, Low: 11, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | R2 | No HTTP->HTTPS redirect | CWE-319 |
| 2 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 3 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 4 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 5 | low | C2 | Cookie without HttpOnly flag | CWE-1004 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 11 | low | H4 | No clickjacking protection | CWE-1023 |
| 12 | low | X2 | CORS origin reflection without credentials (302 redirect response) | CWE-942 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |
| 16 | info | H7 | X-Powered-By disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] No HTTP->HTTPS redirect (`R2`)

- **CWE:** CWE-319
- **Detail:** Verified: http://mobile.twitter.com/ returns 520 (Cloudflare origin error) with no Location header and no HSTS on the error response; https://mobile.twitter.com/ 302 -> https://twitter.com/ (HSTS max-age=631138519; includeSubdomains) -> https://x.com/. The plain-HTTP endpoint is broken rather than redirecting, and the 520 response lacks HSTS, leaving clients on HTTP without upgrade guidance.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

### 2. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie guest_id_marketing lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 3. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie guest_id_ads lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 4. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie personalization_id lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 5. [LOW] Cookie without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookie guest_id lacks HttpOnly; readable by client-side JS.
- **Recommendation:** Add the HttpOnly attribute to the cookie.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 9. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 10. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 11. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 12. [LOW] CORS origin reflection without credentials (302 redirect response) (`X2`)

- **CWE:** CWE-942
- **Detail:** Verified: GET https://mobile.twitter.com/ with Origin: https://evil.example returns 302 -> https://twitter.com/ with access-control-allow-origin: https://evil.example but WITHOUT access-control-allow-credentials. The reflection occurs on the redirect response (mobile.twitter.com is being retired in favor of twitter.com/x.com); without credentials, impact is limited.
- **Recommendation:** Echo the Origin only after validating against an allow-list; avoid reflecting untrusted origins.

### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 15. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare envoy
- **Recommendation:** Consider hiding or shortening the Server header.

### 16. [INFO] X-Powered-By disclosure (`H7`)

- **CWE:** CWE-200
- **Detail:** X-Powered-By: Express
- **Recommendation:** Remove the X-Powered-By header.

## Evidence (raw response observations)

```json
{
  "http_status": 520,
  "https_status": 302,
  "content_type": "text/plain; charset=utf-8",
  "title": "",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 302,
  "path_robots": 200,
  "robots_found": true
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
