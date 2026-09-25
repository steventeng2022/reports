# Security Audit Report — bing.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bing.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bing.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 4, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | T3 | HTTP redirect does not go to HTTPS | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] HTTP redirect does not go to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://bing.com/ redirected to http://www.bing.com/ (not an HTTPS URL).

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.bing.com/?toWww=1&redig=C693351F041D49E08BBBB7337B3E80F3

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.bing.com/?toWww=1&redig=C693351F041D49E08BBBB7337B3E80F3

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.bing.com/?toWww=1&redig=C693351F041D49E08BBBB7337B3E80F3

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.bing.com/?toWww=1&redig=C693351F041D49E08BBBB7337B3E80F3

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.bing.com/?toWww=1&redig=C693351F041D49E08BBBB7337B3E80F3

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
