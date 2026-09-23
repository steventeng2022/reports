# Security Audit Report — profiles.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://profiles.google.com/ |
| Bug bounty program | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| Listed scope domain | google.com |
| Test date | 2026-09-23 18:46 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **13** (High: 0, Medium: 1, Low: 6, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | R2 | No HTTP->HTTPS redirect | CWE-319 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | C1 | Cookie without Secure flag | CWE-614 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | I2 | Deprecated P3P header present | CWE-1038 |
| 13 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [MEDIUM] No HTTP->HTTPS redirect (`R2`)

- **CWE:** CWE-319
- **Detail:** Verified: http://profiles.google.com/ returns 404 (HTML, no redirect to HTTPS) on port 80. The 404 response also carries a deprecated P3P header (CP="This is not a P3P policy!...").
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie NID lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie NID lacks Secure attribute; transmitted over HTTP.
- **Recommendation:** Add the Secure attribute to the cookie.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: ESF
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: ESF
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Deprecated P3P header present (`I2`)

- **CWE:** CWE-1038
- **Detail:** Verified: http://profiles.google.com/ 404 response sends P3P: CP="This is not a P3P policy! See g.co/p3phelp". P3P is obsolete; header can be removed.
- **Recommendation:** Review and remediate per CWE guidance.

### 13. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "http_status": 404,
  "https_status": 404,
  "content_type": "text/html; charset=utf-8",
  "title": "Error 404 (Not Found)!!1",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 404,
  "path_robots": 404
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
