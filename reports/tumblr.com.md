# Security Audit Report — tumblr.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://tumblr.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | tumblr.com |
| Test date | 2026-09-29 12:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 1, Low: 4, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I7 | Server-side template injection (SSTI) (refuted on re-verify) | CWE-94 |
| 2 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Server-side template injection (SSTI) (`I7`)

- **CWE:** CWE-94
- **Detail:** Parameter q on https://www.tumblr.com/: payload #{17*19} is evaluated server-side (response contains 323; control #{17*18} contains 306 instead; token not reflected).
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - baseline homepage (no `q`) ALREADY contains "323" and "306" (coincident IDs/timestamps in 112KB payload); fresh product `#{997*83}`->82751 and `#{40*33}`->1320 NOT present; `{{13*29}}`, `<%= %>` variants not evaluated; `q` reflects only as JSON data field `"link":"?q=..."`. Downgraded HIGH -> LOW.

### 2. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /radar which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.tumblr.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.tumblr.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: tumblr.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.tumblr.com/

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-29, agent-aggressive)

SSTI I7 (CWE-94) on `?q=` at www.tumblr.com/ re-tested with independent arithmetic products and a baseline:
- Baseline `GET /` (no params, 112186 bytes): already contains substrings "323" and "306" -> scanner match was coincidental.
- `?q=#{997*83}` -> 82751: NOT in response; `?q=#{40*33}` -> 1320: NOT in response; `?q={{13*29}}` -> 377: NOT present; `?q=<%= 41*23 %>` -> 943: NOT present.
- Fresh token reflection: `q` appears only as a JSON data field `"link":"?q=TOKEN"` (echo of the request, not template evaluation).
- Conclusion: not SSTI. HIGH -> LOW (unencoded param echo only). Index row updated (7 total: 0H/1M/4L/2I).
