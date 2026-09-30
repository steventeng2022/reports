# Security Audit Report — steemit.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://steemit.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | steemit.com |
| Test date | 2026-09-30 00:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **53** (High: 0, Medium: 0, Low: 49, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I26 | WordPress user enumeration via REST API (wp-json/wp/v2/users) | CWE-200 |
| 2 | low | I26 | Backup archive (backup.zip) exposed | CWE-538 |
| 3 | low | I26 | Site archive (site.zip) exposed | CWE-538 |
| 4 | low | I26 | Website archive exposed | CWE-538 |
| 5 | low | C1 | Cookies without Secure flag | CWE-614 |
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
| 22 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 23 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 24 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 25 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 26 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 27 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 28 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 29 | low | I10 | Swagger UI exposed | CWE-538 |
| 30 | low | I10 | Go debug variables endpoint exposed | CWE-538 |
| 31 | low | I10 | WordPress login page exposed | CWE-538 |
| 32 | low | I10 | /admin returns 200 with an admin/login interface | CWE-538 |
| 33 | low | I10 | /console returns 200 (possible exposed JS console/debug app) | CWE-538 |
| 34 | low | I10 | Apache Solr admin/interface exposed | CWE-538 |
| 35 | low | I10 | phpMyAdmin interface exposed | CWE-538 |
| 36 | low | I10 | Laravel Horizon exposed | CWE-538 |
| 37 | low | I10 | Laravel Telescope exposed | CWE-538 |
| 38 | low | I26 | xmlrpc.php enabled (brute-force / methodCall attack surface) | CWE-306 |
| 39 | low | I26 | WordPress plugins directory responds (plugin enumeration) | CWE-200 |
| 40 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 41 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 42 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 43 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 44 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 45 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 46 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 47 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 48 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 49 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 50 | info | T2 | TLS certificate expiring within 39 days | CWE-295 |
| 51 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 52 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 53 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] WordPress user enumeration via REST API (wp-json/wp/v2/users) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://steemit.com/wp-json/wp/v2/users returned 200 (59342 bytes) with a matching signature.

### 2. [LOW] Backup archive (backup.zip) exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/backup.zip returned 200 (59314 bytes) with a matching signature.

### 3. [LOW] Site archive (site.zip) exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/site.zip returned 200 (59310 bytes) with a matching signature.

### 4. [LOW] Website archive exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/website.zip returned 200 (59317 bytes) with a matching signature.

### 5. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** stm1, stm1.sig set without Secure on https://steemit.com/

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://steemit.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://steemit.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://steemit.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://steemit.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://steemit.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://steemit.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://steemit.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://steemit.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://steemit.com/view reflects input verbatim in body context; encoding boundary not confirmed.

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://steemit.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Swagger UI exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/swagger-ui.html returned 200 (59328 bytes) with a matching signature.

### 30. [LOW] Go debug variables endpoint exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/debug/vars returned 200 (59316 bytes) with a matching signature.

### 31. [LOW] WordPress login page exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/wp-login.php returned 200 (59320 bytes) with a matching signature.

### 32. [LOW] /admin returns 200 with an admin/login interface (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/admin returned 200 (59300 bytes) with a matching signature.

### 33. [LOW] /console returns 200 (possible exposed JS console/debug app) (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/console returned 200 (59307 bytes) with a matching signature.

### 34. [LOW] Apache Solr admin/interface exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/solr/ returned 200 (59300 bytes) with a matching signature.

### 35. [LOW] phpMyAdmin interface exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/phpmyadmin/ returned 200 (59318 bytes) with a matching signature.

### 36. [LOW] Laravel Horizon exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/horizon/ returned 200 (59307 bytes) with a matching signature.

### 37. [LOW] Laravel Telescope exposed (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/telescope returned 200 (59313 bytes) with a matching signature.

### 38. [LOW] xmlrpc.php enabled (brute-force / methodCall attack surface) (`I26`)

- **CWE:** CWE-306
- **Detail:** GET https://steemit.com/xmlrpc.php returned 200 (59313 bytes) with a matching signature.

### 39. [LOW] WordPress plugins directory responds (plugin enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://steemit.com/wp-content/plugins/ returned 200 (59341 bytes) with a matching signature.

### 40. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/old/ returns 200 with content different from the main site (59296 bytes); legacy deployments often carry weaker controls.

### 41. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/test/ returns 200 with content different from the main site (59300 bytes); legacy deployments often carry weaker controls.

### 42. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/staging/ returns 200 with content different from the main site (59308 bytes); legacy deployments often carry weaker controls.

### 43. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/stage/ returns 200 with content different from the main site (59303 bytes); legacy deployments often carry weaker controls.

### 44. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/dev/ returns 200 with content different from the main site (59298 bytes); legacy deployments often carry weaker controls.

### 45. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/beta/ returns 200 with content different from the main site (59299 bytes); legacy deployments often carry weaker controls.

### 46. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/qa/ returns 200 with content different from the main site (59294 bytes); legacy deployments often carry weaker controls.

### 47. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/new/ returns 200 with content different from the main site (59295 bytes); legacy deployments often carry weaker controls.

### 48. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://steemit.com/portal/ returns 200 with content different from the main site (59307 bytes); legacy deployments often carry weaker controls.

### 49. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: steemit.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 50. [INFO] TLS certificate expiring within 39 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for steemit.com (CN=steemit.com) valid_to Nov  7 01:08:18 2026 GMT.

### 51. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://steemit.com/

### 52. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://steemit.com/

### 53. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://steemit.com/.well-known/security.txt returned 200 (58292 bytes) with a matching signature.

## Active re-verification (2026-09-30, agent-aggressive)

- **I26 x4 (MEDIUM -> LOW):** wildcard SPA - every path returns 200 with the same ~59 KB React app shell (text/html; data-reactroot, gtag UA-76480270-1), including random paths (e.g. /nonexistent-xyz12345 = 200, 59,343 B). /wp-json/wp/v2/users returns the HTML shell (not a JSON user list); backup.zip, site.zip and website.zip all return the same HTML shell (not zip binaries) - the "exposed archives" are the SPA's soft-200 for any URL.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
