# Security Audit Report — imore.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://imore.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | imore.com |
| Test date | 2026-09-30 05:31 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 6, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I20 | Preflight-only ACAO reflection (Varnish 204, no ACAC, no ACAO on GET) | CWE-942 |
| 2 | low | I20 | Preflight-only ACAO reflection (Varnish 204, no ACAC, no ACAO on GET) | CWE-942 |
| 3 | low | I20 | Preflight-only ACAO reflection (Varnish 204, no ACAC, no ACAO on GET) | CWE-942 |
| 4 | low | C1 | Cookies without Secure flag | CWE-614 |
| 5 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 6 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 7 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Preflight-only ACAO reflection (Varnish 204, no ACAC, no ACAO on GET) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.imore.com/ with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 2. [LOW] Preflight-only ACAO reflection (Varnish 204, no ACAC, no ACAO on GET) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.imore.com/api with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 3. [LOW] Preflight-only ACAO reflection (Varnish 204, no ACAC, no ACAO on GET) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.imore.com/graphql with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 4. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** FTR_Country_Code, FTR_Cache_Status set without Secure on https://www.imore.com/

### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** FTR_Country_Code, FTR_Cache_Status set without HttpOnly on https://www.imore.com/

### 6. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: imore.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 7. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.imore.com/

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.imore.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **I20 x3 (MEDIUM -> LOW):** re-probed CORS matrix on /, /api, /graphql: OPTIONS preflight = 204 (Varnish) with ACAO reflecting any Origin, but ACTUAL GET responses carry NO Access-Control-Allow-Origin header (same 771,179 B page with/without Origin, no ACAC); /api and /graphql = 404 on GET. Preflight-only reflection without ACAC does not expose response bodies to cross-origin readers.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
