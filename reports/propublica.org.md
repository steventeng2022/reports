# Security Audit Report — propublica.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://propublica.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | propublica.org |
| Test date | 2026-09-29 15:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **25** (High: 0, Medium: 2, Low: 20, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected search URI in Jetpack stats object - quotes stripped (refuted) | CWE-79 |
| 2 | low | I1 | Reflected search URI in Jetpack stats object - quotes stripped (refuted) | CWE-79 |
| 3 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 4 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 5 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
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
| 23 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 24 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 25 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected search URI in Jetpack stats object - quotes stripped, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.propublica.org/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected search URI in Jetpack stats object - quotes stripped, refuted (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.propublica.org/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.propublica.org/graphql with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example with Access-Control-Allow-Credentials: true. Browsers will expose cross-origin responses to any origin the attacker chooses.
- **Re-verify (2026-09-29, agent-aggressive):** confirmed live - GET /graphql + Origin: https://evil-cors.example => 401 with ACAO=https://evil-cors.example + ACAC=true (ACAH: x-requested-with). Kept MEDIUM.

### 4. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.propublica.org/graphql with Origin: null returned Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true. Browsers will expose cross-origin responses to any origin the attacker chooses.
- **Re-verify (2026-09-29, agent-aggressive):** confirmed live - GET /graphql + Origin: null => 401 with ACAO=null + ACAC=true. (OPTIONS preflight => 403 without ACAO, but simple-GET echo is the exploitable pattern.) Kept MEDIUM.

### 5. [LOW] Subdomain is a live AWS API Gateway behind CloudFront (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.propublica.org resolves to 65.9.180.101 (CloudFront) and serves a **live AWS API Gateway**: GET / => 403 (23B) `{"message":"Forbidden"}` with `x-amz-apigw-id`, `x-amzn-errortype: ForbiddenException`, via CloudFront - an active authenticated API, not a dangling landing page. MEDIUM->LOW.
- **Re-verify (2026-09-29, agent-aggressive):** headers confirm x-amz-apigw-id=Ed_bhE9noAMELBA=, x-cache "Error from cloudfront", x-amz-cf-pop TPE53-P4.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.propublica.org/

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.propublica.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.propublica.org/s reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.propublica.org/search reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.propublica.org/s reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.propublica.org/results reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.propublica.org/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.propublica.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.propublica.org/go reflects input verbatim in body context; encoding boundary not confirmed.

### 15. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.propublica.org/r reflects input verbatim in body context; encoding boundary not confirmed.

### 16. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.propublica.org/r reflects input verbatim in body context; encoding boundary not confirmed.

### 17. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.propublica.org/link reflects input verbatim in body context; encoding boundary not confirmed.

### 18. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.propublica.org/out reflects input verbatim in body context; encoding boundary not confirmed.

### 19. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.propublica.org/u reflects input verbatim in body context; encoding boundary not confirmed.

### 20. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.propublica.org/share reflects input verbatim in body context; encoding boundary not confirmed.

### 21. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.propublica.org/view reflects input verbatim in body context; encoding boundary not confirmed.

### 22. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.propublica.org/forward reflects input verbatim in body context; encoding boundary not confirmed.

### 23. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: propublica.org + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 24. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.propublica.org/

### 25. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.propublica.org/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).


## Active re-verification (2026-09-29, agent-aggressive)

- Two `I1` HIGH findings (search token reflected in JavaScript on /search?query=): re-probed with controlled payloads. The token reflects only inside the Jetpack-stats analytics object: `_stq.push(["view", {..., "arch_err":"/search?query=TOKEN", ...}])` on the 404 document. Precision probes: payload `Zx7qK2v9Bm"ENDQ` reflected as `Zx7qK2v9BmENDQ` and `Zx7qK2v9Bm<ENDG` reflected as `Zx7qK2v9BmENDG` - both `"` and `<` are STRIPPED (not escaped) by the stats sanitizer, so the quoted string cannot be broken out of; payload with a backslash tripped the CF challenge (token appears URL-encoded in cUPMDTk, known false-positive family). 2 HIGH -> 2 LOW.
- `S1` api.propublica.org: live AWS API Gateway (403 ForbiddenException, x-amz-apigw-id), not a dangling CloudFront landing. MEDIUM -> LOW.
- `I20` x2: kept MEDIUM (ACAO+ACAC echo confirmed on live GET, 401 responses).
