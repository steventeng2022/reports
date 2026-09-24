# Security Audit Report — myfitnesspal.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://myfitnesspal.com/ |
| Bug bounty program | [UNDER ARMOUR](https://bugcrowd.com/underarmour) |
| Listed scope domain | myfitnesspal.com |
| Test date | 2026-09-24 00:04 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **14** (High: 0, Medium: 1, Low: 9, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | X2 | CORS origin reflection with credentials | CWE-942 |
| 2 | low | C1 | Cookie without Secure flag | CWE-614 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | low | H4 | No clickjacking protection | CWE-1023 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] CORS origin reflection with credentials (`X2`)

- **CWE:** CWE-942
- **Detail:** Verified (reproducible): GET https://myfitnesspal.com/ with Origin: https://evil.example returns 301 -> https://www.myfitnesspal.com/ and the www 200 (text/html) responds with access-control-allow-origin: https://evil.example AND access-control-allow-credentials: true. The landing page itself is public, but the credentialed reflection pattern warrants triage against authenticated/JSON API endpoints. HSTS is present (max-age=31536000; includeSubDomains; preload).
- **Recommendation:** Echo the Origin only after validating against an allow-list; avoid reflecting untrusted origins.

### 2. [LOW] Cookie without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** Cookie __cf_bm lacks Secure attribute; transmitted over HTTP.
- **Context:** http response
- **Recommendation:** Add the Secure attribute to the cookie.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: cloudflare
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://myfitnesspal.com/",
  "https_status": 301,
  "content_type": "text/html",
  "title": "301 Moved Permanently",
  "path_gitconfig": 403,
  "path_envfile": 403,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 301
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
