# Security Audit Report — agoda.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://agoda.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | agoda.com |
| Test date | 2026-09-30 03:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 2, Low: 5, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 2 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 3 | low | I22 | Public booking SPA shell from robots.txt (no hidden data) | CWE-538 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | C1 | Cookies without Secure flag | CWE-614 |
| 6 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.agoda.com/graphql with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example with Access-Control-Allow-Credentials: true. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 2. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.agoda.com/graphql with Origin: null returned Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 3. [LOW] Public booking SPA shell from robots.txt (no hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /book/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.agoda.com/

### 5. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** agoda.prius set without Secure on https://www.agoda.com/

### 6. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** agoda.version.03, agoda.attr.fe, agoda.price.trk.01, agoda.price.01, agoda.user.03, agoda.analytics, agoda.prius set without HttpOnly on https://www.agoda.com/

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: agoda.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.agoda.com/

### 9. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://www.agoda.com/.well-known/security.txt returned 200 (326 bytes) with a matching signature.

## Active re-verification (2026-09-30, agent-aggressive)

- **I20 x2 (MEDIUM KEPT):** /graphql re-probed with Origin "https://evil-cors.example" = 200 (113 B application/json) Access-Control-Allow-Origin: https://evil-cors.example + Access-Control-Allow-Credentials: true; Origin null = ACAO: null + ACAC: true - live arbitrary-origin CORS reflection with credentials (thenextweb W31 precedent).
- **I22 (MEDIUM -> LOW):** /book/ re-probed = 200 (1,752,103 B) Agoda SPA shell (agoda-spa / agoda-splash divs, server-injected observability config, embedded refund-policy JSON) - public booking app, no hidden data.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
