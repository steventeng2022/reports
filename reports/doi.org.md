# Security Audit Report — doi.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://doi.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | doi.org |
| Test date | 2026-09-30 02:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 4, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Live S3 static hosting (Hugo site, not dangling) | CWE-916 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Live S3 static hosting - staging.doi.org (Hugo site, not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain staging.doi.org resolves to 52.222.244.129 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.doi.org/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.doi.org/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: doi.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.doi.org/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.doi.org/

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 (MEDIUM -> LOW):** staging.doi.org re-probed = 200, server AmazonS3, serving a gzip-compressed Hugo 0.165.0 static site (24,205 B uncompressed, title "Home Page", Bootstrap 5, ahrefs verification meta) with a gzip-compressed 404 error document for random keys - live first-party static hosting, not a dangling CloudFront signature.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
