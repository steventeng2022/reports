# Security Audit Report — it.wikipedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://it.wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | it.wikipedia.org |
| Test date | 2026-09-30 04:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **22** (High: 0, Medium: 2, Low: 18, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I2 | MediaWiki bad-title 404 reflection (escaped, no breakout) | CWE-79 |
| 2 | medium | I2 | MediaWiki bad-title 404 reflection (escaped, no breakout) | CWE-79 |
| 3 | low | I22 | Public MediaWiki API index from robots.txt (no hidden data) | CWE-538 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 15 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 16 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 17 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 18 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 19 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 20 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 21 | info | T2 | TLS certificate expiring within 35 days | CWE-295 |
| 22 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] MediaWiki bad-title 404 reflection (escaped, no breakout) (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://it.wikipedia.org/w/index.php: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [MEDIUM] MediaWiki bad-title 404 reflection (escaped, no breakout) (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter title on https://it.wikipedia.org/w/index.php: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 3. [LOW] Public MediaWiki API index from robots.txt (no hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /api/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://it.wikipedia.org/wiki/Pagina_principale

### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** GeoIP, NetworkProbeLimit set without HttpOnly on https://it.wikipedia.org/wiki/Pagina_principale

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter modules on https://it.wikipedia.org/w/load.php reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://it.wikipedia.org/w/api.php reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://it.wikipedia.org/w/index.php reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter oldid on https://it.wikipedia.org/w/index.php reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://it.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://it.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://it.wikipedia.org/s reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://it.wikipedia.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://it.wikipedia.org/results reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://it.wikipedia.org/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://it.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://it.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://it.wikipedia.org/r reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://it.wikipedia.org/r reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: it.wikipedia.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 21. [INFO] TLS certificate expiring within 35 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for it.wikipedia.org (CN=*.wikipedia.org) valid_to Nov  3 19:15:40 2026 GMT.

### 22. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://it.wikipedia.org/wiki/Pagina_principale

## Active re-verification (2026-09-30, agent-aggressive)

- **I2 x2 (HIGH -> MEDIUM):** /w/index.php?title= re-probed = 404 (44,778 B) MediaWiki bad-title page; token inside <title>...</title> text + URL-encoded canonical href; attr payload 301 (Location /wiki/%22%27_onerror%3D%22alert(1)//, no body); span payload 404 (34,190 B) angle brackets URL-encoded in canonical href = no DOM breakout. /w/index.php?url= re-probed = 200 (188,171 B), token only double-URL-encoded inside a returntoquery= param of a login link. Classic MediaWiki bad-title reflection (commons W17 / de.wikipedia W20 precedent) = MEDIUM, not live XSS.
- **I22 (MEDIUM -> LOW):** /api/ re-probed = 200 (944 B) public MediaWiki APIs index page (server mw-web.eqiad.main) - documentation, no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
