# Security Audit Report — prntscr.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://prntscr.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | prntscr.com |
| Test date | 2026-09-30 01:07 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 4, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I10 | Actuator-style path returns the default HTML page (soft-200 catch-all, not JSON) | CWE-538 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Actuator-style path returns the default HTML page (soft-200 catch-all, not JSON) (`I10`)

- **CWE:** CWE-538
- **Detail:** GET https://prnt.sc/actuator/env returned 200 (16347 bytes) with a matching signature.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://prnt.sc/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://prnt.sc/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: prntscr.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://prnt.sc/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://prnt.sc/

## Active re-verification (2026-09-30, agent-aggressive)

- **I10 (MEDIUM -> LOW):** /actuator/env re-probed = 200 (16,347 B) but content-type is text/html with the "Screenshot by Lightshot" default page, not application/json; /actuator/health (16,365 B) and /actuator (16,329 B) return the same ~16.3 KB HTML page - the Lightshot app serves its default page for these paths (catch-all), so this is not an exposed Spring Boot actuator environment endpoint.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
