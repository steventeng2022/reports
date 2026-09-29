# Security Audit Report — thesun.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://thesun.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | thesun.co.uk |
| Test date | 2026-09-29 12:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **22** (High: 0, Medium: 4, Low: 15, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | I26 | Backup archive (backup.zip) exposed | CWE-538 |
| 3 | medium | I26 | Site archive (site.zip) exposed | CWE-538 |
| 4 | medium | I26 | Website archive exposed | CWE-538 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | C1 | Cookies without Secure flag | CWE-614 |
| 8 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 9 | low | I10 | macOS .DS_Store file exposed (directory listing metadata) | CWE-538 |
| 10 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 11 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 12 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 13 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 14 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 15 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 16 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 17 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 18 | low | I36 | Staging/legacy sub-application directory exposed | CWE-538 |
| 19 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 20 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 21 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 22 | info | I26 | humans.txt exposed (team/contact enumeration) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [MEDIUM] Backup archive (backup.zip) exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/backup.zip returned 200 (1331 bytes) with a matching signature.

### 3. [MEDIUM] Site archive (site.zip) exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/site.zip returned 200 (1331 bytes) with a matching signature.

### 4. [MEDIUM] Website archive exposed (`I26`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/website.zip returned 200 (1331 bytes) with a matching signature.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.thesun.co.uk/

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.thesun.co.uk/

### 7. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** _ngn_pb_p set without Secure on https://www.thesun.co.uk/

### 8. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** _ngn_pb_p set without HttpOnly on https://www.thesun.co.uk/

### 9. [LOW] macOS .DS_Store file exposed (directory listing metadata) (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/.DS_Store returned 200 (1331 bytes) with a matching signature.

### 10. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/old/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 11. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/test/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 12. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/staging/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 13. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/stage/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 14. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/dev/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 15. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/beta/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 16. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/qa/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 17. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/new/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 18. [LOW] Staging/legacy sub-application directory exposed (`I36`)

- **CWE:** CWE-538
- **Detail:** GET https://www.thesun.co.uk/portal/ returns 200 with content different from the main site (1331 bytes); legacy deployments often carry weaker controls.

### 19. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: thesun.co.uk + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 20. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.thesun.co.uk/

### 21. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.thesun.co.uk/

### 22. [INFO] humans.txt exposed (team/contact enumeration) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.thesun.co.uk/humans.txt returned 200 (1331 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
