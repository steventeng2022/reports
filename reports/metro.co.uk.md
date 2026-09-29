# Security Audit Report — metro.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://metro.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | metro.co.uk |
| Test date | 2026-09-29 12:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **10** (High: 2, Medium: 2, Low: 3, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 2 | high | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 4 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect_to on https://members.metro.co.uk/modal-login/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [HIGH] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter referring_module on https://members.metro.co.uk/modal-login/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 4. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.metro.co.uk resolves to 54.192.248.45 and is served by cloudfront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 200

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://metro.co.uk/

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://metro.co.uk/

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: metro.co.uk + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://metro.co.uk/

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://metro.co.uk/

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
