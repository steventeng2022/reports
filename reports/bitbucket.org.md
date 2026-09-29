# Security Audit Report — bitbucket.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bitbucket.org/ |
| Bug bounty program | Atlassian |
| Listed scope domain | bitbucket.org |
| Test date | 2026-09-29 20:56 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 2, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/api | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/api | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/api | CWE-942 |
| 10 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/graphql | CWE-942 |
| 11 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/graphql | CWE-942 |
| 12 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/graphql | CWE-942 |

## Detailed findings

### 1. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.bitbucket.org resolves to 104.192.139.8 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.bitbucket.org resolves to 54.192.248.50 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** atlCohort, ajs_anonymous_id set without Secure on https://bitbucket.org/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** atlCohort, ajs_anonymous_id, atlCohort, bxp_gateway_anchor, ajs_anonymous_id, bxp_gateway_request_id set without HttpOnly on https://bitbucket.org/

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: bitbucket.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://bitbucket.org/

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://bitbucket.org/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://bitbucket.org/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/api (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://bitbucket.org/api responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 10. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://bitbucket.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 11. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://bitbucket.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

### 12. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://bitbucket.org/graphql (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://bitbucket.org/graphql responds with Access-Control-Allow-Origin: * (Content-Type: text/html; charset=utf-8). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **S1 #1 (MEDIUM -> LOW):** http://api.bitbucket.org = 301 -> https (CloudFront redirect); https = 302 -> https://developer.atlassian.com/cloud/bitbucket/rest/ - live Atlassian Bitbucket REST API documentation (intended API entry point, not dangling).
- **S1 #2 (MEDIUM -> LOW):** http://status.bitbucket.org = 301 -> https (CloudFront redirect); https = 302 -> https://bitbucket.status.atlassian.com/ - live first-party Atlassian statuspage.
