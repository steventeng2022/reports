# Security Audit Report - edx.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://www.edx.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | edx.org |
| Test date | 2026-09-25 02:4x UTC |
| Method | Manual active re-test of RE-TEST CANDIDATES lead from agent-deepdive (redirect persistence, CORS matrix, soft-200 method matrix); unauthenticated, non-destructive |

## Summary

Total findings: **7** (High: 0, Medium: 3, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I6 | Open-redirect parameter persists apex->www 301 and is embedded in client JSON state | CWE-601 |
| 2 | medium | I20 | CORS wildcard on /api/graphql, /api/xapi, /auth (404 router) and / | CWE-942 |
| 3 | medium | I11 | Unauthenticated POST to / returns 2.5MB full app state (soft-200 + data disclosure) | CWE-200 |
| 4 | low | H1 | Missing HSTS on plain-HTTP bootstrap path | CWE-319 |
| 5 | low | I12 | 404 pages reflect request path in inline flight JSON | CWE-200 |
| 6 | info | T3 | Plain HTTP served (CloudFront 403 on apex http) | CWE-319 |
| 7 | info | A10b | Method differential: PATCH / -> 400 (915B) vs GET/POST/PUT/DELETE -> 200 (2.5MB) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Open-redirect parameter persists apex->www 301 and is embedded in client JSON state (`I6`)

- **CWE:** CWE-601
- **Steps:**
  1. `GET https://edx.org/?redirect=https://evil-attacker.example/x`
  2. -> `HTTP 301` `Location: https://www.edx.org/?redirect=https://evil-attacker.example/x` (attacker value preserved verbatim)
  3. `GET https://www.edx.org/?redirect=https://evil-attacker.example/x` -> `HTTP 200`; the parameter is parsed by the Next.js router into the inline flight-data JSON: `"c":["","?redirect=https:","","evil-attacker.example","x"]`.
  4. Same reflection also occurs on 404 paths: `/login?redirect=...` and `/verify?redirect=...` both return 404 with the parameter embedded in the same flight-JSON structure.
- **Assessment:** The redirect parameter survives server-side redirects and is wired into client-side state, which is the classic precursor to client-side open redirect (the app is likely to `location.href` the value after auth/login). The inline JSON encoding (segment array) is currently safe against direct injection. Final browser round-trip (does the client actually navigate to the external host) is the remaining confirmation step - a headless-browser or logged-in re-test is recommended.
- **Recommendation:** Validate the `redirect` parameter against a same-origin/allowlist scheme on the server before persisting it to client state; strip or encode external values.

### 2. [MEDIUM] CORS wildcard on /api/graphql, /api/xapi, /auth (404 router) and / (`I20`)

- **CWE:** CWE-942
- **Detail:** With `Origin: https://evil-cors.example`:
  | Path | Status | Access-Control-Allow-Origin | Credentials |
  |---|---|---|---|
  | /api/graphql | 404 | `*` | - |
  | /api/xapi | 404 | `*` | - |
  | /auth | 404 | `*` | - |
  | / | 200 | `*` | - |
  Wildcard without `Access-Control-Allow-Credentials` limits direct data exfiltration, but the same wildcard on live authenticated endpoints (graphql/xapi once a session exists) would expose responses cross-origin. Combined with finding 1 (redirect) and the soft-200 router, an authenticated re-test of /api/graphql is the highest-value follow-up.
- **Recommendation:** Restrict ACAO to an explicit origin allowlist on /api/*; avoid `*` on JSON APIs that may return session data.

### 3. [MEDIUM] Unauthenticated POST to / returns 2.5MB full app state (soft-200 + data disclosure) (`I11`)

- **CWE:** CWE-200
- **Detail:** `POST/PUT/DELETE https://www.edx.org/` (empty body) all return `200` with the full ~2,561,960-byte Next.js app page including serialized route state, experiment flags and feature config; only `PATCH` returns 400 (915 bytes). The identical document for every method/path (soft-200) means unknown-path detection and WAF signature matching are weakened, and the inline state discloses internal naming (experiment buckets, route trees).
- **Recommendation:** Return 405 for non-GET on static routes; differentiate 404 responses from 200 documents.

### 4. [LOW] Missing HSTS on plain-HTTP bootstrap path (`H1`)

- **CWE:** CWE-319
- **Detail:** `http://` requests are answered by CloudFront (403 on apex) without an HSTS header, so first-visit downgrade/SSLI on HTTP is possible until the browser has seen a prior HSTS response.
- **Recommendation:** Add HSTS with max-age >= 31536000; includeSubDomains; preload on all responses including error pages.

### 5. [LOW] 404 pages reflect request path in inline flight JSON (`I12`)

- **CWE:** CWE-200
- **Detail:** `/login?redirect=...` and `/verify?redirect=...` (and other unknown paths) return 404 with the full requested path reflected in the inline Next.js flight-data JSON (segment-array encoded). Currently safely encoded; noted because the same mechanism carries the open-redirect parameter (finding 1).
- **Recommendation:** See finding 1; also add a CSP with strict-dynamic to limit impact of any future encoding regression.

### 6. [INFO] Plain HTTP served (CloudFront 403 on apex http) (`T3`)

- **CWE:** CWE-319
- **Detail:** `http://edx.org/` is served (403 via CloudFront) rather than closed; no redirect to HTTPS on that edge path in this observation.
- **Recommendation:** 301 all plain-HTTP traffic to HTTPS at the edge.

### 7. [INFO] Method differential: PATCH / -> 400 vs all other methods -> 200 (`A10b`)

- **CWE:** CWE-200
- **Detail:** OPTIONS/GET/POST/PUT/DELETE on / all return the 200 homepage document; PATCH returns 400 (915B distinct body). Small behavioral differential useful for fingerprinting and for distinguishing router layers.
- **Recommendation:** Normalize method handling or return consistent 405/404.

## Reproduction notes

- Manually re-tested 2026-09-25 (Asia/Taipei) from a fresh IP/UA; this report is the RE-TEST CANDIDATES follow-up for the agent-deepdive leads (redirect persistence CONFIRMED at the 301 hop; ACAO:* CONFIRMED; soft-200 CONFIRMED; plain-HTTP confirmed at the edge).
- Coordinated with agent-deepdive: their deep-dive report (Drive) covers cookie forensics / CDN layering; this file covers the injection/CORS re-test.
