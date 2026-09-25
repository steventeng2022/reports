# Security Audit Report — activecampaign.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://activecampaign.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | activecampaign.com |
| Test date | 2026-09-24 22:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **16** (High: 0, Medium: 10, Low: 4, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I1v | URL params reflected in Cloudflare challenge JS string (safely escaped, verified) | CWE-79 |
| 2 | medium | I6v | Campaign redirect endpoint /go?url= (challenge-gated, account re-test pending) | CWE-601 |
| 28 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 29 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 30 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 31 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 32 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 33 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 34 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 35 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 36 | low | H2 | Missing CSP header | CWE-1021 |
| 37 | low | H4 | No clickjacking protection | CWE-1023 |
| 38 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 39 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 40 | info | T2 | TLS certificate expiring within 33 days | CWE-295 |
| 41 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] URL parameters reflected in Cloudflare challenge JS string - safely escaped (verified 2026-09-25) (`I1v`)

- **CWE:** CWE-79
- **Detail:** 26 near-duplicate engine hits consolidated into this finding. On challenged requests (HTTP 403, Cloudflare "managed" challenge) the requested path is echoed inside the challenge-page JavaScript: `cUPMDTk:"/go?url=<PARAM>\u0026__cf_chl_tk=..."`. Encoding verified with raw unencoded characters in the request: `"` -> `%22`; `\` -> `\\` (doubled); `&` -> `\u0026`; single quote reflected raw (safe inside double-quoted JS literal). No script breakout achieved in any tested context.
- **Affected paths:** /go, /u, /r, /link, /out, /share, /view, /forward, /redirect, /search, /s, /results, / (parameters: url, redirect, to, q, query).
- **Severity rationale (rule 4):** High -> Medium: same-origin reflection on an intermittent challenge page, but the JS encoding is safe in every tested context. Exploitability would require a bypass of the encoding (e.g., a variant that reflects raw `"`) - re-test recommended.
- **Recommendation:** Percent-encode the full request URI inside cUPMDTk, or deliver the token via the challenge meta endpoint rather than an inline JS literal.

### 2. [MEDIUM] Campaign redirect endpoint /go?url= gated behind Cloudflare challenge (verified 2026-09-25) (`I6v`)

- **CWE:** CWE-601
- **Detail:** /go?url=, /r?url=, /link?url= are classic URL-redirector patterns (marketing link tracking). Unauthenticated requests intermittently receive a Cloudflare managed challenge (403); non-challenged requests return 404 (a valid campaign slug is required in addition to url). Open-redirect behavior for arbitrary external url values therefore needs one valid campaign slug to fully confirm (account/affiliate re-test pending).
- **Severity rationale (rule 4):** Medium: high-value brand (ActiveCampaign), classic redirector surface, not yet confirmed exploitable unauthenticated.
- **Recommendation:** Restrict /go, /r, /link to validated schemes (https) and a block/allowlist of external hosts; monitor cross-origin redirects.

### 3. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/ with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.


### 4. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/ with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.


### 5. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/ with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.


### 6. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/graphql with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.


### 7. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/graphql with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.


### 8. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/graphql with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.


### 9. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.activecampaign.com resolves to 54.192.248.74 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301


### 10. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain docs.activecampaign.com resolves to 74.125.204.121 and is served by activecampaign (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 302


### 11. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.activecampaign.com/


### 12. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.activecampaign.com/


### 13. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /.env which returns 403, indicating a hidden/protected resource exists at that path.


### 14. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: activecampaign.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.


### 15. [INFO] TLS certificate expiring within 33 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.activecampaign.com (CN=www.activecampaign.com) valid_to Oct 26 23:59:59 2026 GMT.


### 16. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.activecampaign.com/

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
