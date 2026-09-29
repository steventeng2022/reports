# Security Audit Report — youtu.be

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://youtu.be/ |
| Bug bounty program | Google |
| Listed scope domain | youtu.be |
| Test date | 2026-09-29 16:39 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **20** (High: 0, Medium: 1, Low: 17, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I10 | Apache Solr admin/interface exposed | CWE-538 |
| 14 | low | I10 | phpMyAdmin interface exposed | CWE-538 |
| 15 | low | I10 | Laravel Horizon exposed | CWE-538 |
| 16 | low | I10 | Laravel Telescope exposed | CWE-538 |
| 17 | low | I26 | WordPress plugins directory responds (plugin enumeration) | CWE-200 |
| 18 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 19 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 20 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /api/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter feature on https://www.youtube.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.youtube.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.youtube.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.youtube.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.youtube.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.youtube.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.youtube.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.youtube.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.youtube.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.youtube.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.youtube.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Apache Solr admin/interface exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://www.youtube.com/solr/ returned 200 (298924 bytes) with a matching signature.

### 14. [LOW] phpMyAdmin interface exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://www.youtube.com/phpmyadmin/ returned 200 (298998 bytes) with a matching signature.

### 15. [LOW] Laravel Horizon exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://www.youtube.com/horizon/ returned 200 (298935 bytes) with a matching signature.

### 16. [LOW] Laravel Telescope exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://www.youtube.com/telescope returned 200 (299060 bytes) with a matching signature.

### 17. [LOW] WordPress plugins directory responds (plugin enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.youtube.com/wp-content/plugins/ returned 200 (299002 bytes) with a matching signature.

### 18. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: youtu.be + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 19. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.youtube.com/?feature=youtu.be

### 20. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.youtube.com/.well-known/security.txt returned 200 (202 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
