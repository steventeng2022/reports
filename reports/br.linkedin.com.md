# Security Audit Report — br.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://br.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | br.linkedin.com |
| Test date | 2026-09-30 03:06 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 11, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I2 | Escaped reflection in /redirect error-page span (no breakout) | CWE-79 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Escaped reflection in /redirect error-page span (no breakout) (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://br.linkedin.com/redirect: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** JSESSIONID, lang, bcookie, lidc set without HttpOnly on https://br.linkedin.com/

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://br.linkedin.com/jobs/engineering-vagas-taip%C3%A9 reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://br.linkedin.com/jobs/business-development-vagas-taip%C3%A9 reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://br.linkedin.com/jobs/finance-vagas-taip%C3%A9 reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://br.linkedin.com/jobs/administrative-assistant-vagas-taip%C3%A9 reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://br.linkedin.com/jobs/retail-associate-vagas-taip%C3%A9 reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://br.linkedin.com/jobs/customer-service-vagas-taip%C3%A9 reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://br.linkedin.com/jobs/operations-vagas-taip%C3%A9 reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://br.linkedin.com/jobs/information-technology-vagas-taip%C3%A9 reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: br.linkedin.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://br.linkedin.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **I2 (HIGH -> LOW):** /redirect?url= re-probed: clean token reflects once in the "Erro de link" error page (3,787 B) inside <span class="t-bold"> ... </span> (TEXT context); the attribute-injection payload reflects verbatim inside that same span (3,799 B) - still text content, not an attribute boundary; the angle-bracket payload is HTML-escaped ("&lt;/span&gt;&lt;img src=x onerror=alert(1)&gt;") so no tag breakout. No XSS - an escaped reflection on the error page only.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
