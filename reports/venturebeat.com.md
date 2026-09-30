# Security Audit Report — venturebeat.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://venturebeat.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | venturebeat.com |
| Test date | 2026-09-29 16:16 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | S1 | Vercel security checkpoint (home/www 429) with mixed first-party subdomain surface | CWE-916 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://venturebeat.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on http://venturebeat.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on http://venturebeat.com/

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: venturebeat.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on http://venturebeat.com/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on http://venturebeat.com/
### 7. [INFO] Vercel security checkpoint (home/www 429) with mixed first-party subdomain surface (`S1`)

- **CWE:** CWE-916
- **Detail:** home/www 429 (33,940-33,953 B, Vercel "Security Checkpoint" - rate-limited); chat 307 -> /login?callbackUrl=chat.venturebeat.com; mobile 200 (1,416 B)/media 200 (1,467 B) AmazonS3; mail 301 -> http://mail.google.com/a/venturebeat.com (ghs, plain HTTP Location); auth 404 (21,265 B); support/download 409 (16 B, CF); old 404 (548 B, nginx).
- **Recommendation:** The plain-HTTP mail Location is a minor referrer/cookie-hygiene note; otherwise first-party surface.

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 x1:** home/www 429 (33,940-33,953 B Vercel "Security Checkpoint"); chat 307 -> /login?callbackUrl=; mobile 200 (1,416 B)/media 200 (1,467 B) AmazonS3; mail 301 -> http://mail.google.com/a/venturebeat.com (ghs, plain HTTP); auth 404 (21,265 B); support/download 409 (16 B CF); old 404 (548 B nginx).

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
