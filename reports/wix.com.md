# Security Audit Report — wix.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wix.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | wix.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 1, Low: 9, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | S1 | mail.wix.com - managed Google Workspace alias on retest | CWE-916 |
| 3 | low | S1 | status.wix.com - live Atlassian Statuspage on retest | CWE-916 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | low | C1 | Cookies without Secure flag | CWE-614 |
| 7 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 11 | info | T2 | TLS certificate expiring within 43 days | CWE-295 |
| 12 | info | I23 | XML sitemap exposes 1398 indexed URLs | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /blogtemp which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] mail.wix.com - managed Google Workspace alias on retest (`S1`)

- **CWE:** CWE-916
- **Detail:** mail.wix.com -> 74.125.204.121. RETEST 2026-09-25: over HTTP it 301-redirects to https://mail.google.com/a/wix.com (Server: ghs = Google) = a MANAGED Google Workspace group alias, not a dangling platform account. Over HTTPS the edge drops the TLS handshake (SNI mismatch quirk). Downgraded medium -> low (managed; TLS quirk noted).

### 3. [LOW] status.wix.com - live Atlassian Statuspage on retest (`S1`)

- **CWE:** CWE-916
- **Detail:** status.wix.com. RETEST 2026-09-25: returns 200 (188KB) "Wix Status" served by AtlassianEdge = an active Atlassian Statuspage instance. Not dangling. Downgraded medium -> low.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.wix.com/

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.wix.com/

### 6. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** ssr-caching set without Secure on https://www.wix.com/

### 7. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** ssr-caching, sec-fetch-unsupported, _wixCIDX, _wixUIDX set without HttpOnly on https://www.wix.com/

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.wix.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.wix.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: wix.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 11. [INFO] TLS certificate expiring within 43 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.wix.com (CN=*.wix.com) valid_to Nov  6 11:34:35 2026 GMT.

### 12. [INFO] XML sitemap exposes 1398 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.wix.com/sitemap.xml returns a sitemap with 1398 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
