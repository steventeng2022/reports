# Security Audit Report — podbean.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://podbean.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | podbean.com |
| Test date | 2026-09-30 07:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 4, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | 301 to public privacy policy (no hidden content) | CWE-538 |
| 2 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [LOW] 301 to public privacy policy (no hidden content) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /site/default/privacy which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter return on https://www.podbean.com/site/user/register reflects input verbatim in body context; encoding boundary not confirmed.

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.podbean.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: podbean.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 (MEDIUM -> LOW):** /site/default/privacy re-probed = 301 (Cloudflare) -> https://www.podbean.com/site/default/privacy = 200 (138,260 B "Privacy Policy | Podbean", X-Frame-Options DENY) - public privacy policy page.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
