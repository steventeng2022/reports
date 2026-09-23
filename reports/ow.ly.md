# Security Audit Report — ow.ly

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ow.ly/ |
| Bug bounty program | [Hootsuite](https://www.hootsuite.com/security) |
| Listed scope domain | ow.ly |
| Test date | 2026-09-23 20:18 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 5, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | R2 | No HTTP->HTTPS redirect (dormant service, 404 on both schemes) | CWE-319 |
| 6 | info | P3 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] No HTTP->HTTPS redirect (dormant service, 404 on both schemes) (`R2`)

- **CWE:** CWE-319
- **Detail:** Verified: http://ow.ly/ returns 404 with no Location header and no HSTS on the error response; https://ow.ly/ also returns 404. The Ow.ly shortener appears dormant (root not found on both schemes), so the missing HTTP->HTTPS redirect has limited exposure; the 404 error response lacking HSTS is noted for completeness.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

### 6. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "http_status": 404,
  "https_status": 404,
  "content_type": "text/html; charset=UTF-8",
  "title": "Not Found",
  "path_gitconfig": 404,
  "path_envfile": 403,
  "path_securitytxt": 404,
  "path_robots": 301
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
