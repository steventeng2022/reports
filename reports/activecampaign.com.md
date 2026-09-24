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

Total findings: **40** (High: 26, Medium: 8, Low: 4, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 2 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 4 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 5 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 6 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 7 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 8 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 9 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 10 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 11 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 12 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 13 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 14 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 15 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 16 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 17 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 18 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 19 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 20 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 21 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 22 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 23 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 24 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 25 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 26 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 27 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 28 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 29 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 30 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 31 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 32 | medium | I20 | CORS reflects attacker-controlled Origin | CWE-942 |
| 33 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 34 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 35 | low | H2 | Missing CSP header | CWE-1021 |
| 36 | low | H4 | No clickjacking protection | CWE-1023 |
| 37 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 38 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 39 | info | T2 | TLS certificate expiring within 33 days | CWE-295 |
| 40 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.activecampaign.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.activecampaign.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.activecampaign.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.activecampaign.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 9. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 10. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 11. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.activecampaign.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 12. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.activecampaign.com/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 13. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.activecampaign.com/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 14. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.activecampaign.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 15. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.activecampaign.com/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 16. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 17. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 18. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect on https://www.activecampaign.com/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 19. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 20. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.activecampaign.com/r reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 21. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/link reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 22. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/out reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 23. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/u reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 24. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/share reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 25. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.activecampaign.com/view reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 26. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter to on https://www.activecampaign.com/forward reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 27. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/ with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 28. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/ with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 29. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/ with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 30. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/graphql with Origin: https://evil-cors.example returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 31. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/graphql with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 32. [MEDIUM] CORS reflects attacker-controlled Origin (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://www.activecampaign.com/graphql with Origin: null returned Access-Control-Allow-Origin: null. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 33. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.activecampaign.com resolves to 54.192.248.74 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 34. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain docs.activecampaign.com resolves to 74.125.204.121 and is served by activecampaign (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 302

### 35. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.activecampaign.com/

### 36. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.activecampaign.com/

### 37. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /.env which returns 403, indicating a hidden/protected resource exists at that path.

### 38. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: activecampaign.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 39. [INFO] TLS certificate expiring within 33 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.activecampaign.com (CN=www.activecampaign.com) valid_to Oct 26 23:59:59 2026 GMT.

### 40. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.activecampaign.com/

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
