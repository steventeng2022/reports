# Security Audit Report — ca.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ca.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ca.linkedin.com |
| Test date | 2026-09-24 13:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **8** (High: 1, Medium: 0, Low: 5, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I2 | Reflected XSS via attribute injection | CWE-79 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://ca.linkedin.com/redirect: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** JSESSIONID, lang, bcookie, lidc set without HttpOnly on https://ca.linkedin.com/

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://ca.linkedin.com/jobs/engineering-jobs-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://ca.linkedin.com/jobs/business-development-jobs-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://ca.linkedin.com/jobs/finance-jobs-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://ca.linkedin.com/jobs/administrative-assistant-jobs-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://ca.linkedin.com/

### 8. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://ca.linkedin.com/.well-known/security.txt returned 200 (267 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
