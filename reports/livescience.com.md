# Security Audit Report — livescience.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://livescience.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | livescience.com |
| Test date | 2026-09-29 20:24 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 6, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 2 | low | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 3 | low | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 4 | low | C1 | Cookies without Secure flag | CWE-614 |
| 5 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 6 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 7 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.livescience.com/ with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 2. [LOW] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.livescience.com/api with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 3. [LOW] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.livescience.com/graphql with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 4. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** FTR_Country_Code, FTR_Cache_Status set without Secure on https://www.livescience.com/

### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** FTR_Country_Code, FTR_Cache_Status set without HttpOnly on https://www.livescience.com/

### 6. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: livescience.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 7. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.livescience.com/

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.livescience.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **I20 #1/#2/#3 (MEDIUM -> LOW):** re-sent OPTIONS preflights with Origin: https://evil-cors.example to /, /api, /graphql - all return 204 with Access-Control-Allow-Origin: <echoed origin> but NO Access-Control-Allow-Credentials, and the actual GET responses carry NO Access-Control-Allow-Origin header at all (GET / = 200 no ACAO; GET /api and /graphql = 404 no ACAO). A preflight-only echo without credentials cannot expose cross-origin response bodies (the real response has no CORS grant), so downgraded to LOW.
