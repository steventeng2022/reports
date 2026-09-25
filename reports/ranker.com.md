# Security Audit Report — ranker.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ranker.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ranker.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | info | T2 | TLS certificate expiring within 26 days | CWE-295 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://ranker.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://ranker.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://ranker.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** geo_ip_country, geo_ip_is_us, geo_ip_is_ca, geo_ip_is_eu, geo_ip_city, geo_ip_continent_code, geo_ip_region_code, geo_ip_latitude, geo_ip_longitude set without HttpOnly on https://ranker.com/

### 5. [INFO] TLS certificate expiring within 26 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for ranker.com (CN=ranker.com) valid_to Oct 20 16:13:55 2026 GMT.

### 6. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://ranker.com/

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://ranker.com/

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
