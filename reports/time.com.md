# Security Audit Report — time.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://time.com/ |
| Bug bounty program | TIME |
| Listed scope domain | time.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 1, Low: 3, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | mail.time.com - CloudFront dist + edge function, 404 default on all paths | CWE-916 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | T2 | TLS certificate expiring within 18 days | CWE-295 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] mail.time.com - CloudFront distribution + edge function, 404 default on all paths (`S1`)

- **CWE:** CWE-916
- **Detail:** mail.time.com -> 3.169.55.64 (CloudFront 8ad72c38f68920ee5b40a6b6070b6b0). RETEST 2026-09-25: an edge CloudFront function (x-cache: LambdaGeneratedResponse) 301-redirects every path to a trailing-slash variant (/actuator -> /actuator/, /x -> /x/); the slash variants return the CloudFront DEFAULT 404 page (8475B, NOINDEX/NO-CACHE). Distribution is active but the origin serves nothing = dangling-content takeover candidate (claim the origin bucket/distribution). KEPT as medium.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://time.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://time.com/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: time.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] TLS certificate expiring within 18 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for time.com (CN=*.time.com) valid_to Oct 12 16:26:59 2026 GMT.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://time.com/

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
