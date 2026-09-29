# Security Audit Report — thenextweb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://thenextweb.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | thenextweb.com |
| Test date | 2026-09-29 23:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 2, Low: 3, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 2 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://thenextweb.com/ with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example with Access-Control-Allow-Credentials: true. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 2. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://thenextweb.com/ with Origin: null returned Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://thenextweb.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://thenextweb.com/

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: thenextweb.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://thenextweb.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
