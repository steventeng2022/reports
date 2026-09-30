# Security Audit Report — ocw.mit.edu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ocw.mit.edu/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ocw.mit.edu |
| Test date | 2026-09-30 06:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 4 | info | T2 | TLS certificate expiring within 29 days | CWE-295 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://ocw.mit.edu/ | CWE-942 |
| 8 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://ocw.mit.edu/ | CWE-942 |
| 9 | info | I19 | Wildcard CORS (Access-Control-Allow-Origin: *) on https://ocw.mit.edu/ | CWE-942 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://ocw.mit.edu/

### 2. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://ocw.mit.edu/

### 3. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: ocw.mit.edu + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 4. [INFO] TLS certificate expiring within 29 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for ocw.mit.edu (CN=www.ocw.mit.edu) valid_to Oct 28 18:35:16 2026 GMT.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://ocw.mit.edu/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://ocw.mit.edu/

### 7. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://ocw.mit.edu/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://ocw.mit.edu/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

### 8. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://ocw.mit.edu/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://ocw.mit.edu/ responds with Access-Control-Allow-Origin: * (Content-Type: application/xml). Any site can read responses cross-origin.

### 9. [INFO] Wildcard CORS (Access-Control-Allow-Origin: *) on https://ocw.mit.edu/ (`I19`)

- **CWE:** CWE-942
- **Detail:** GET https://ocw.mit.edu/ responds with Access-Control-Allow-Origin: * (Content-Type: text/html). Any site can read responses cross-origin.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
