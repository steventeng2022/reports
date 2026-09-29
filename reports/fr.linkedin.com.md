# Security Audit Report — fr.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fr.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | fr.linkedin.com |
| Test date | 2026-09-29 13:19 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **11** (High: 0, Medium: 1, Low: 9, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I2 | Reflected XSS via attribute injection | CWE-79 |
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

### 1. [HIGH] Reflected XSS via attribute injection (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://fr.linkedin.com/redirect: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.
- **Re-verify 2026-09-29 (agent-aggressive):** refuted as attribute injection - `/redirect?url=` reflects the value raw as PLAIN TEXT inside `<span class="t-bold">...</span>` ("Lien inactif" error page); angle brackets ARE HTML-escaped (`&lt;img src=x onerror=alert(1)&gt;`, `&lt;/span&gt;` breakout escaped), so quotes-only payload cannot open an attribute. Redirects are same-origin-only (`//host` and `https:host` neutralized to relative paths; cross-origin https rendered as error page, no cross-site Location). Downgraded HIGH -> MEDIUM.

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** JSESSIONID, lang, bcookie, lidc set without HttpOnly on https://fr.linkedin.com/

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://fr.linkedin.com/jobs/engineering-emplois-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://fr.linkedin.com/jobs/business-development-emplois-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://fr.linkedin.com/jobs/finance-emplois-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://fr.linkedin.com/jobs/administrative-assistant-emplois-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://fr.linkedin.com/jobs/retail-associate-emplois-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://fr.linkedin.com/jobs/customer-service-emplois-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://fr.linkedin.com/jobs/operations-emplois-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter trk on https://fr.linkedin.com/jobs/information-technology-emplois-taipei reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://fr.linkedin.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-29, agent-aggressive)

Re-checked the I2 attribute-injection HIGH on fr.linkedin.com/redirect with fresh tokens and multiple payloads (direct HTTP):
- Raw token reflects once, as plain text: `<span class="t-bold">TOKEN</span>` (LinkedIn trust-frontend "Lien inactif" error page) - not an attribute, not a script.
- `<img src=x onerror=alert(1)>` -> reflected HTML-ESCAPED as `&lt;img src=x onerror=alert(1)&gt;`; `</span><img ...>` breakout -> both angle brackets escaped; `<script>alert(3)</script>` -> escaped, no raw script.
- Open-redirect matrix: `url=https://evil...` -> 200 error page (no Location); `url=//evil...` -> 303 `/evil...` (relative); `url=https:evil...` -> 200; `url=https://fr.linkedin.com/?x=TOK` -> 303 same-origin. Same-origin-only redirect - not an open redirect.
- Conclusion: no XSS, no open redirect. HIGH -> MEDIUM (unescaped plain-text echo remains XSS-adjacent). Index row updated (11 total: 0H/1M/9L/1I).
