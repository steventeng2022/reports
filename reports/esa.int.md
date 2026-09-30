# Security Audit Report — esa.int

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://esa.int/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | esa.int |
| Test date | 2026-09-30 04:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | /esatv/layout/set now 301 to www host (no hidden data) | CWE-538 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | T2 | TLS certificate expiring within 35 days | CWE-295 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] /esatv/layout/set now 301 to www host (no hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /esatv/layout/set which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.esa.int/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.esa.int/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: esa.int + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] TLS certificate expiring within 35 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.esa.int (CN=www.esa.int) valid_to Nov  3 23:59:59 2026 GMT.

### 6. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.esa.int/

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.esa.int/

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 (MEDIUM -> LOW):** /esatv/layout/set re-probed = 301 -> https://www.esa.int/esatv/layout/set (www host) - no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
