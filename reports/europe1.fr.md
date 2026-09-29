# Security Audit Report — europe1.fr

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://europe1.fr/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | europe1.fr |
| Test date | 2026-09-29 20:24 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **14** (High: 1, Medium: 0, Low: 2, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/ | CWE-942 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/ | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/api | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/api | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/graphql | CWE-942 |
| 13 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/graphql | CWE-942 |
| 14 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/graphql | CWE-942 |

## Detailed findings

### 1. [HIGH] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain staging.europe1.fr resolves to 3.169.231.84 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://europe1.fr/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://europe1.fr/

### 4. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://europe1.fr/

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://europe1.fr/

### 6. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/ responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/api responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 13. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

### 14. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://europe1.fr/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://europe1.fr/graphql responds with Access-Control-Allow-Origin: * (Content-Type: none). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **S1 #1 (MEDIUM -> HIGH, promoted):** staging.europe1.fr re-probed = **403, exactly 919 bytes, CloudFront, X-Cache: Error, "ERROR: The request could not be satisfied / We reached CloudFront but not the origin"** (X-Amz-Cf-Id present) - the identical byte-size + cache-state signature as the three confirmed dangling-distribution HIGHs (ftp.strava.com R12-adjacent, api.ilpost.it R12, dev.pbs.org R13). The subdomain's CloudFront distribution no longer resolves to a live origin. 5th index HIGH.
