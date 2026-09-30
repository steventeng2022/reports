# Security Audit Report — bitly.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bitly.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bitly.com |
| Test date | 2026-09-30 07:27 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 8, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | 301 to public home (no hidden content) | CWE-538 |
| 2 | low | S1 | First-party branded redirect / live Atlassian statuspage (not dangling) | CWE-916 |
| 3 | low | S1 | First-party branded redirect / live Atlassian statuspage (not dangling) | CWE-916 |
| 4 | low | S1 | First-party branded redirect / live Atlassian statuspage (not dangling) | CWE-916 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 9 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] 301 to public home (no hidden content) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /pages/home which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] First-party branded redirect / live Atlassian statuspage (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain test.bitly.com resolves to 67.199.248.13 and is served by bitly (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 302

### 3. [LOW] First-party branded redirect / live Atlassian statuspage (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain stage.bitly.com resolves to 67.199.248.12 and is served by bitly (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 302

### 4. [LOW] First-party branded redirect / live Atlassian statuspage (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.bitly.com resolves to 54.192.248.2 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://bitly.com/

### 6. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** _xsrf set without HttpOnly on https://bitly.com/

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter categories on https://bitly.com/pages/marketplace reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: bitly.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 9. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://bitly.com/

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://bitly.com/

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

### 12. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://bitly.com/.well-known/security.txt returned 200 (95 bytes) with a matching signature.

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 x3 (MEDIUM -> LOW):** test.bitly.com and stage.bitly.com re-probed = 302 (nginx) -> https://bitly.com/pages/landing/branded-short-domains-powered-by-bitly?bsd=`subdomain` = 200 (109,888 B "Custom Domain by Bitly") - first-party branded short-domain landing pages; status.bitly.com = 200 (77,324 B) server AtlassianEdge title "Bitly Status" (live Atlassian status page via CloudFront) - none show the 915 B dangling CloudFront signature.

- **I22 (MEDIUM -> LOW):** /pages/home re-probed = 301 (nginx) -> https://bitly.com/pages/home = 200 (155,142 B "Bitly Connections Platform | Short URLs, QR Codes, and More") - public home page.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
