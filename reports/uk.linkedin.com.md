# Security Audit Report — uk.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://uk.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | uk.linkedin.com |
| Test date | 2026-09-30 03:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 5, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I2 | Escaped reflection in /redirect error-page span (no breakout) | CWE-79 |
| 2 | low | I2 | Escaped reflection in /redirect error-page span (no breakout) | CWE-79 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Escaped reflection in /redirect error-page span (no breakout) (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://uk.linkedin.com/redirect: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 2. [LOW] Escaped reflection in /redirect error-page span (no breakout) (`I2`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://uk.linkedin.com/redirect: injecting "\"' onerror=\"alert(1)//" yields an unquoted onerror handler. Event fires on render.

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** sdui_ver set without Secure on https://uk.linkedin.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** sdui_ver, JSESSIONID, lang, bcookie, lidc set without HttpOnly on https://uk.linkedin.com/

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: uk.linkedin.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://uk.linkedin.com/.well-known/security.txt returned 200 (267 bytes) with a matching signature.

## Active re-verification (2026-09-30, agent-aggressive)

- **I2 x2 (HIGH -> LOW):** /redirect?url= re-probed: clean token reflects once in the "Link Error" page (3,736 B) inside <span class="t-bold"> ... </span> (TEXT context); attribute-injection payload reflects verbatim inside that same span (3,748 B) - still text content, not an attribute boundary; angle-bracket payload HTML-escaped ("&lt;/span&gt;&lt;img src=x onerror=alert(1)&gt;") = no tag breakout. Same verdict as br.linkedin.com (W35 R25).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
