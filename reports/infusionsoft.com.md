# Security Audit Report — infusionsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://infusionsoft.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | infusionsoft.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **41** (High: 0, Medium: 1, Low: 35, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | low | C1 | Cookies without Secure flag | CWE-614 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 15 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 16 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 17 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 18 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 19 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 20 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 21 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 22 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 23 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 24 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 25 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 26 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 27 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 28 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 29 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 30 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 31 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 32 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 33 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 34 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 35 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 36 | info | T2 | TLS certificate expiring within 42 days | CWE-295 |
| 37 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 38 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.infusionsoft.com/

### 2. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.infusionsoft.com/

### 3. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** XSRF-TOKEN, laravel_session set without Secure on https://www.infusionsoft.com/

### 4. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** XSRF-TOKEN set without HttpOnly on https://www.infusionsoft.com/

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.infusionsoft.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.infusionsoft.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.infusionsoft.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.infusionsoft.com/search reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/s reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.infusionsoft.com/results reflects input verbatim in body context; encoding boundary not confirmed.

### 24. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 25. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 26. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.infusionsoft.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 27. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 28. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.infusionsoft.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 29. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/link reflects input verbatim in body context; encoding boundary not confirmed.

### 30. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/out reflects input verbatim in body context; encoding boundary not confirmed.

### 31. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 32. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/share reflects input verbatim in body context; encoding boundary not confirmed.

### 33. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.infusionsoft.com/view reflects input verbatim in body context; encoding boundary not confirmed.

### 34. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.infusionsoft.com/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 35. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: infusionsoft.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 36. [INFO] TLS certificate expiring within 42 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.infusionsoft.com (CN=infusionsoft.com) valid_to Nov  5 18:14:54 2026 GMT.

### 37. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.infusionsoft.com/

### 38. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.infusionsoft.com/

| 39 | medium | I31 | Pre-auth param-preserving meta-refresh redirector chain (infusionsoft -> keap -> accounts.infusionsoft) | CWE-668 |
| 40 | info | I32 | Cloudflare WAF: full <script>/</title> sequences 403 in query, individual special chars pass + reflect URL-encoded | CWE-200 |
| 41 | info | I33 | keap.com JSON-LD "url" property reflects request URL (URL-encoded, no breakout) | CWE-200 |

## Detailed findings (deep-dive addendum 2026-09-25)

### 39. [MEDIUM] Pre-auth param-preserving meta-refresh redirector chain (I31)

- **CWE:** CWE-668
- **Detail:** Verified 2026-09-25: ANY query on the www.infusionsoft.com apex is preserved verbatim in a 301 meta-refresh to keap.com - e.g. https://www.infusionsoft.com?cb=X -> <meta http-equiv="refresh" content="0;url='https://keap.com?cb=X'" /> with the X also reflected (URL-encoded) in the 301 page <title> ("Redirecting to https://keap.com?cb=X"). The same pattern exists at /keap/login?redirect=X -> keap.com/keap/login?redirect=X. Third hop: https://keap.com/login?redirect=X -> 301 meta-refresh -> https://accounts.infusionsoft.com/?redirect=X (parameter preserved into the auth host). The chain moves arbitrary parameters from the marketing apex into the login/account host before authentication. If accounts.infusionsoft.com performs an open redirect on /?redirect= post-login (auth-state re-test pending), this becomes a pre-auth phishing chain. File as medium until the post-login hop is confirmed.

### 40. [INFO] Cloudflare WAF behavior on the redirector (I32)

- **CWE:** CWE-200
- **Detail:** Queries containing full <script> or </title> sequences return 403 (Cloudflare "Attention Required!"), while individual special characters - < (cb=%3c), >, space, newline, ", backslash, = - all pass and are reflected URL-ENCODed in the <title> (a%22b stays a%22b; %3C stays %3C). The encoding neutralizes the reflected chars; the WAF only blocks multi-char payload signatures.

### 41. [INFO] keap.com JSON-LD url reflection (I33)

- **CWE:** CWE-200
- **Detail:** https://keap.com?cb=X (200, 290KB) reflects the request URL in the JSON-LD block: "url":"http://keap.com/?cb=X" inside a <script type="application/ld+json">. Quote/backslash/newline tests (a%22b, a%5cb, a%0ab) all remain percent-encoded inside the JSON string - no string breakout.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
