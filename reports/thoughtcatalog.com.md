# Security Audit Report — thoughtcatalog.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://thoughtcatalog.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | thoughtcatalog.com |
| Test date | 2026-09-29 12:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 14, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 2 | low | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 3 | low | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 4 | low | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 5 | low | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 6 | low | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 7 | low | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 8 | low | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 9 | low | H2 | Missing CSP header | CWE-1021 |
| 10 | low | H4 | No clickjacking protection | CWE-1023 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 13 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 14 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 15 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 16 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 17 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://thoughtcatalog.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - endpoint returns HTTP 404 (SiteArc error page); fresh token reflects only inside the SiteArc `_stq.push` analytics object with `<`/`"`/`:` characters stripped; breakout payload `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> LOW.

### 2. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://thoughtcatalog.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - endpoint returns HTTP 404 (SiteArc error page); fresh token reflects only inside the SiteArc `_stq.push` analytics object with `<`/`"`/`:` characters stripped; breakout payload `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> LOW.

### 3. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://thoughtcatalog.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - endpoint returns HTTP 404 (SiteArc error page); fresh token reflects only inside the SiteArc `_stq.push` analytics object with `<`/`"`/`:` characters stripped; breakout payload `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> LOW.

### 4. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://thoughtcatalog.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - endpoint returns HTTP 404 (SiteArc error page); fresh token reflects only inside the SiteArc `_stq.push` analytics object with `<`/`"`/`:` characters stripped; breakout payload `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> LOW.

### 5. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://thoughtcatalog.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - endpoint returns HTTP 404 (SiteArc error page); fresh token reflects only inside the SiteArc `_stq.push` analytics object with `<`/`"`/`:` characters stripped; breakout payload `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> LOW.

### 6. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://thoughtcatalog.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - endpoint returns HTTP 404 (SiteArc error page); fresh token reflects only inside the SiteArc `_stq.push` analytics object with `<`/`"`/`:` characters stripped; breakout payload `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> LOW.

### 7. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://thoughtcatalog.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - endpoint returns HTTP 404 (SiteArc error page); fresh token reflects only inside the SiteArc `_stq.push` analytics object with `<`/`"`/`:` characters stripped; breakout payload `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> LOW.

### 8. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://thoughtcatalog.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - endpoint returns HTTP 404 (SiteArc error page); fresh token reflects only inside the SiteArc `_stq.push` analytics object with `<`/`"`/`:` characters stripped; breakout payload `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> LOW.

### 9. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://thoughtcatalog.com/

### 10. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://thoughtcatalog.com/

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://thoughtcatalog.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://thoughtcatalog.com/r reflects input verbatim in body context; encoding boundary not confirmed.

### 13. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://thoughtcatalog.com/u reflects input verbatim in body context; encoding boundary not confirmed.

### 14. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: thoughtcatalog.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 15. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://thoughtcatalog.com/

### 16. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://thoughtcatalog.com/

### 17. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-29, agent-aggressive)

Re-checked all 8 HIGH I1 findings ("reflected XSS in JavaScript context" on /search, /results, /redirect, /link, /out) with fresh unique tokens and script-breakout payloads via direct HTTP:
- All six endpoints now return **HTTP 404**; the token reflects only in the SiteArc 404-page snippet: `{"srv":"thoughtcatalog.com","arch_err":"/search?q=TOKEN",...}` inside `_stq.push(...)`.
- Breakout probes: `q=x</script><img src=x onerror=alert(1)>` -> payload characters stripped (no raw `onerror`, no `%3C` leftover, no HTML escaping); `url=...x=a%22>` quote also stripped. No JS dialog / no img emit possible from raw HTTP.
- Conclusion: scanner I1 heuristic tripped on the analytics object, not a breakable JS string. All 8 HIGH -> LOW. Index row updated (17 total: 0H/0M/14L/3I).
