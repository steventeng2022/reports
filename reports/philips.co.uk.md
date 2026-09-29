# Security Audit Report — philips.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://philips.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | philips.co.uk |
| Test date | 2026-09-29 19:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 3, Low: 6, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | I4 | Reflected input in HTML attribute context | CWE-79 |
| 3 | medium | I4 | Reflected input in HTML attribute context | CWE-79 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 10 | info | T2 | TLS certificate expiring within 33 days | CWE-295 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /healthcare/crsc/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [MEDIUM] Reflected input in HTML attribute context (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.philips.co.uk/ reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 3. [MEDIUM] Reflected input in HTML attribute context (`I4`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.philips.co.uk/ reflects the token inside a quoted attribute; escape boundary should be verified (quote/angle breakout tested).

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** notice_settings, user_country set without HttpOnly on https://www.philips.co.uk/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.philips.co.uk/go reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.philips.co.uk/go reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.philips.co.uk/go reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.philips.co.uk/go reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: philips.co.uk + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 10. [INFO] TLS certificate expiring within 33 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.philips.co.uk (CN=www.philips.co.uk) valid_to Oct 31 21:42:26 2026 GMT.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.philips.co.uk/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
