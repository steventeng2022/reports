# Security Audit Report — goodreads.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://goodreads.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | goodreads.com |
| Test date | 2026-09-30 04:59 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 8, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Public blog RSS feed from robots.txt (no hidden data) | CWE-538 |
| 2 | low | S1 | First-party AWS Midway SSO / CF origin 403 (not dangling) | CWE-916 |
| 3 | low | S1 | First-party AWS Midway SSO / CF origin 403 (not dangling) | CWE-916 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | C1 | Cookies without Secure flag | CWE-614 |
| 6 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Public blog RSS feed from robots.txt (no hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /blog/list_rss which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] First-party AWS Midway SSO / CF origin 403 (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain admin.goodreads.com resolves to 65.9.180.80 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] First-party AWS Midway SSO / CF origin 403 (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.goodreads.com resolves to 65.9.176.214 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.goodreads.com/

### 5. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** ccsid, locale, _session_id2 set without Secure on https://www.goodreads.com/

### 6. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** ccsid, locale set without HttpOnly on https://www.goodreads.com/

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter language on https://www.goodreads.com/ap/register reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: goodreads.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.goodreads.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 (MEDIUM -> LOW):** /blog/list_rss re-probed = 200 (256,526 B) application/xml - public blog RSS feed, no hidden data.
- **S1 x2 (MEDIUM -> LOW):** admin.goodreads.com re-probed = http 301 (CloudFront) -> https, then 307 -> https://midway-auth.amazon.com/SSO/redirect?redirect_uri=https://admin.goodreads.com:443/...&scope=openid (live AWS Midway SSO, Amazon first-party); api.goodreads.com = https 403 (521 B) "Website Temporarily Unavailable" (origin error) - none show the 915 B dangling CloudFront signature.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
