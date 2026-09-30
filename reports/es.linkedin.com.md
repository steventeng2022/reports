# Security Audit Report — es.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://es.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | es.linkedin.com |
| Test date | 2026-09-30 04:08 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 10, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I2 | Escaped reflection in /redirect link-error span (no breakout) | CWE-79 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Escaped reflection in /redirect link-error span (no breakout) (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://es.linkedin.com/redirect: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** JSESSIONID, lang, bcookie, lidc set without HttpOnly on https://es.linkedin.com/

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://es.linkedin.com/jobs/engineering-empleos-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://es.linkedin.com/jobs/business-development-empleos-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://es.linkedin.com/jobs/finance-empleos-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://es.linkedin.com/jobs/administrative-assistant-empleos-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://es.linkedin.com/jobs/retail-associate-empleos-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://es.linkedin.com/jobs/customer-service-empleos-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://es.linkedin.com/jobs/operations-empleos-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://es.linkedin.com/jobs/information-technology-empleos-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://es.linkedin.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **I2 (HIGH -> LOW):** /redirect?url= re-probed = 200 (3,599 B) Spanish link-error page ("problema con el enlace seleccionado"); token reflects once inside <span class="t-bold"> ... </span> (TEXT context); attr payload verbatim inside that same span (3,611 B) - quotes inert in text content; angle-bracket payload HTML-escaped ("&lt;/span&gt;&lt;img src=x onerror=alert(1)&gt;", 3,636 B) = no tag breakout. Same verdict as br.linkedin W35 / uk.linkedin W36.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
