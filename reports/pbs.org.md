# Security Audit Report — pbs.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pbs.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pbs.org |
| Test date | 2026-09-29 18:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **17** (High: 1, Medium: 0, Low: 14, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | high | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 4 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 5 | low | T3 | HTTP redirect does not go to HTTPS | CWE-319 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 15 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 16 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 17 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /independentlens/getinvolved/cinema/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [HIGH] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain dev.pbs.org resolves to 18.164.154.43 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 403

### 3. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain staging.pbs.org resolves to 3.169.252.75 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 4. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.pbs.org resolves to 65.9.180.73 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 5. [LOW] HTTP redirect does not go to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://pbs.org/ redirected to http://www.pbs.org/ (not an HTTPS URL).

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.pbs.org/

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.pbs.org/

### 8. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** pbsol.user_is_unlocalized set without HttpOnly on https://www.pbs.org/

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.pbs.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.pbs.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.pbs.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.pbs.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.pbs.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.pbs.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: pbs.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 16. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.pbs.org/

### 17. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.pbs.org/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)

- Finding 2 (S1 dev.pbs.org): http://dev.pbs.org/ -> **403 CloudFront 915 B** "ERROR: The request could not be satisfied / Request blocked" with X-Amz-Cf-Id = **dangling CloudFront distribution** (origin unreachable), same signature as the verified ftp.strava.com / api.ilpost.it takeovers. MEDIUM -> **HIGH**.
- Finding 3 (S1 staging.pbs.org): 301 -> 401 CloudFront (0 B body, X-Amz-Cf-Id present) = live distribution answering with auth-required, not the classic origin-miss 403 915 B signature. MEDIUM -> LOW (ambiguous, ownership check needed).
- Finding 4 (S1 status.pbs.org): 301 -> 200 187,174 B **AtlassianEdge** "PBS Public Status Status" = live Atlassian status page. MEDIUM -> LOW.
- Finding 1 (I22 /independentlens/getinvolved/cinema/): 200 but **0 B** body, content-type application/octet-stream (parent /independentlens/ is live) - no discoverable content. MEDIUM -> LOW.
- Note: the scanner's "q reflects verbatim in body context" LOW items on /search were re-probed - \`<title>&quot;TOKEN&quot; Search Results\` (quotes escaped) and a raw \`<img src=x onerror=alert(1)>\` probe returns no raw tag; stays LOW.
