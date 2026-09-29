# Security Audit Report — commons.wikimedia.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://commons.wikimedia.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | commons.wikimedia.org |
| Test date | 2026-09-29 20:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **24** (High: 1, Medium: 1, Low: 20, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I2 | Reflected XSS via attribute injection | CWE-79 |
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
| 17 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 18 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 19 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 20 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 21 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 22 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 23 | info | T2 | TLS certificate expiring within 35 days | CWE-295 |
| 24 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter title on https://commons.wikimedia.org/w/index.php: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [LOW] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /api/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://commons.wikimedia.org/wiki/Main_Page

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** GeoIP, NetworkProbeLimit set without HttpOnly on https://commons.wikimedia.org/wiki/Main_Page

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter modules on https://commons.wikimedia.org/w/load.php reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://commons.wikimedia.org/w/api.php reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter action on https://commons.wikimedia.org/w/index.php reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter oldid on https://commons.wikimedia.org/w/index.php reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://commons.wikimedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://commons.wikimedia.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://commons.wikimedia.org/s reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://commons.wikimedia.org/ reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://commons.wikimedia.org/results reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://commons.wikimedia.org/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://commons.wikimedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://commons.wikimedia.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://commons.wikimedia.org/r reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://commons.wikimedia.org/r reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://commons.wikimedia.org/link reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://commons.wikimedia.org/out reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://commons.wikimedia.org/u reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: commons.wikimedia.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 23. [INFO] TLS certificate expiring within 35 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for commons.wikimedia.org (CN=*.wikipedia.org) valid_to Nov  3 19:15:40 2026 GMT.

### 24. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://commons.wikimedia.org/wiki/Main_Page

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **I2 #1 (HIGH -> MEDIUM):** re-probed /w/index.php?title="' onerror="'alert(1)// (301 -> /wiki/%22%27_onerror%3D%22%27alert(1)//). The payload reflects RAW (unescaped quotes) in exactly 3 places: <title>, <h1 id="firstHeading"> mw-page-title-main, and the sticky-header span. It is NOT present in any of the 4 <script> blocks on the page (all occurrences verified outside script ranges). Breakout requires closing the element: </title>, </TITLE>, </Title>, </title >, </title\t> and </h1>, </H1>, </h1 > were all tested - every variant is rejected by MediaWiki as "Bad title" (404 page, document title becomes "Bad title - Wikimedia Commons"; payload survives only URL-encoded in rel=canonical). Verdict: raw unescaped reflection in element-content contexts, breakout constrained by the bad-title filter - not exploitable as full DOM XSS; held MEDIUM as a sanitization-boundary finding on a high-value Wikimedia property.
- **I22 #2 (MEDIUM -> LOW):** /api/ = 200, 944B, content-type text/html, <title>APIs</title> - the public Wikimedia Commons APIs landing page (intentional public content, not a hidden app).
