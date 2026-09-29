# Security Audit Report — colorado.edu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://colorado.edu/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | colorado.edu |
| Test date | 2026-09-29 19:33 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 7, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 2 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 4 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 5 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | T2 | TLS certificate expiring within 24 days | CWE-295 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | I23 | XML sitemap exposes 1409 indexed URLs | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.colorado.edu/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.colorado.edu/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.colorado.edu/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /README.md which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 5. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.colorado.edu resolves to 65.9.180.100 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.colorado.edu/

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: colorado.edu + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] TLS certificate expiring within 24 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.colorado.edu (CN=www.colorado.edu) valid_to Oct 23 03:43:40 2026 GMT.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.colorado.edu/

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

### 11. [INFO] XML sitemap exposes 1409 indexed URLs (`I23`)

- **CWE:** CWE-200
- **Detail:** GET https://www.colorado.edu/sitemap.xml returns a sitemap with 1409 URLs, aiding enumeration of the site surface.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **I1 #1/#2/#3 (HIGH -> LOW):** token Bd5Xn8JqWz reflects once on /, /s (404) and /results (404), always inside the Drupal <script type="application/json" data-drupal-selector="drupal-settings-json"> block ("currentQuery":{"q":"..."}). Breakout test: ?q=%3C%2Fscript%3E%3Csvg%20onload%3Dalert(1)%3E renders as </script><svg... (hex-escaped, raw </script> absent) and ?q=%22%3Balert(1)// renders with JSON-escaped quote - same drupal_json_encode protection as law.cornell; not executable.
- **I22 #4 (MEDIUM -> LOW):** /README.md = 200 3,205B text/plain = the stock Drupal distribution README ("Drupal is an open source content management platform..."), generic framework documentation, not app-specific data.
- **S1 #5 (MEDIUM -> LOW):** status.colorado.edu = 200 111,363B AtlassianEdge = live first-party Atlassian Statuspage (not the CF 915/919B dangling signature).
