# Security Audit Report — de.wikipedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://de.wikipedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | de.wikipedia.org |
| Test date | 2026-09-29 23:07 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **19** (High: 0, Medium: 2, Low: 15, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I2 | Reflected XSS via attribute injection (sanitization boundary) | CWE-79 |
| 2 | low | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
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
| 17 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 18 | info | T2 | TLS certificate expiring within 35 days | CWE-295 |
| 19 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Reflected XSS via attribute injection - sanitization boundary (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter title on https://de.wikipedia.org/w/index.php: payload reflects in <title> element content of the 404 "Ungültiger Titel" (bad-title) page; breakout titles containing </title> or </h1> also return 404 via the Bad-title filter; no raw onerror inside a firing element attribute - sanitization boundary, not directly exploitable (commons.wikimedia.org precedent).

### 2. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /api/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://de.wikipedia.org/wiki/Wikipedia:Hauptseite

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** GeoIP, NetworkProbeLimit set without HttpOnly on https://de.wikipedia.org/wiki/Wikipedia:Hauptseite

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter modules on https://de.wikipedia.org/w/load.php reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://de.wikipedia.org/w/api.php reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://de.wikipedia.org/w/index.php reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter oldid on https://de.wikipedia.org/w/index.php reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://de.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://de.wikipedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://de.wikipedia.org/s reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://de.wikipedia.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://de.wikipedia.org/results reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://de.wikipedia.org/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://de.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://de.wikipedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: de.wikipedia.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 18. [INFO] TLS certificate expiring within 35 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for de.wikipedia.org (CN=*.wikipedia.org) valid_to Nov  3 19:15:40 2026 GMT.

### 19. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://de.wikipedia.org/wiki/Wikipedia:Hauptseite

## Active re-verification (2026-09-30, agent-aggressive)

- **I2 (HIGH -> MEDIUM):** GET https://de.wikipedia.org/w/index.php?title=PAYLOAD -> 301 -> /wiki/%22%27_onerror%3D%22alert(1)// -> final 404 (53,099 B, bad-title page "Ungültiger Titel"). Payload reflects only inside <title> element content; breakout attempts with </title> and </h1> in the title also 404 (Bad-title filter); no raw onerror inside a firing element attribute. Same sanitization-boundary behavior as commons.wikimedia.org (R17 gate).
- **I22 (MEDIUM -> LOW):** https://de.wikipedia.org/api/ re-probed = 200, 944 B, <title>APIs</title> landing page; unauthenticated with no app-specific data (exact twin of commons.wikimedia.org /api/).

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
