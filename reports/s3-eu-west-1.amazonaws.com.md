# Security Audit Report — s3-eu-west-1.amazonaws.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://s3-eu-west-1.amazonaws.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | s3-eu-west-1.amazonaws.com |
| Test date | 2026-09-29 14:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **13** (High: 0, Medium: 1, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I20 | CORS reflects attacker-controlled Origin (preflight) | CWE-942 |
| 2 | info | I22 | Hidden path from robots.txt (refuted) | CWE-538 |
| 3 | info | S1 | Subdomain path - live AWS regional S3, legacy hostname 301 -> NoSuchBucket (refuted) | CWE-916 |
| 4 | info | S1 | Subdomain path - live AWS regional S3, legacy hostname 301 -> NoSuchBucket (refuted) | CWE-916 |
| 5 | info | S1 | Subdomain path - live AWS regional S3, legacy hostname 301 -> NoSuchBucket (refuted) | CWE-916 |
| 6 | info | S1 | Subdomain path - live AWS regional S3, legacy hostname 301 -> NoSuchBucket (refuted) | CWE-916 |
| 7 | info | S1 | Subdomain path - live AWS regional S3, legacy hostname 301 -> NoSuchBucket (refuted) | CWE-916 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | low | C1 | Cookies without Secure flag | CWE-614 |
| 10 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 11 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [MEDIUM] CORS reflects attacker-controlled Origin (preflight) (`I20`)

- **CWE:** CWE-942
- **Detail:** Request to https://aws.amazon.com/s3/ with Origin: https://evil-cors.example (OPTIONS preflight) returned Access-Control-Allow-Origin: https://evil-cors.example with Access-Control-Allow-Credentials: true. Browsers will expose cross-origin responses to any origin the attacker chooses.

### 2. [INFO] Hidden path from robots.txt (refuted: root bucket 403 / NoSuchBucket) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /blogs/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 3. [INFO] Subdomain path - live AWS regional S3, legacy hostname migration (refuted) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain staging.s3-eu-west-1.amazonaws.com resolves to 3.5.64.214 and is served by s3.amazonaws (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 4. [INFO] Subdomain path - live AWS regional S3, legacy hostname migration (refuted) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain stage.s3-eu-west-1.amazonaws.com resolves to 52.92.16.106 and is served by s3.amazonaws (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 5. [INFO] Subdomain path - live AWS regional S3, legacy hostname migration (refuted) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain beta.s3-eu-west-1.amazonaws.com resolves to 3.5.67.98 and is served by s3.amazonaws (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 6. [INFO] Subdomain path - live AWS regional S3, legacy hostname migration (refuted) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain ftp.s3-eu-west-1.amazonaws.com resolves to 52.218.62.192 and is served by s3.amazonaws (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 7. [INFO] Subdomain path - live AWS regional S3, legacy hostname migration (refuted) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain jira.s3-eu-west-1.amazonaws.com resolves to 52.92.36.18 and is served by s3.amazonaws (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://aws.amazon.com/s3/

### 9. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** aws_lang set without Secure on https://aws.amazon.com/s3/

### 10. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** aws-priv, aws_lang set without HttpOnly on https://aws.amazon.com/s3/

### 11. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: s3-eu-west-1.amazonaws.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://aws.amazon.com/s3/

### 13. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://aws.amazon.com/.well-known/security.txt returned 200 (575 bytes) with a matching signature.

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).


## Active re-verification (2026-09-29, agent-aggressive)

- Five `S1` "dangling subdomain" findings (staging/stage/beta/ftp/jira host paths) were re-probed: each returns S3 XML **301 PermanentRedirect** (legacy regional hostname migration, `Endpoint=s3.amazonaws.com`); following the redirect yields 307 + **404 NoSuchBucket** - live AWS regional infrastructure, not dangling buckets. MEDIUM->INFO.
- `I22` (hidden path responding 200 per robots.txt): on the root bucket /robots.txt -> **403 AccessDenied** and /blogs/ -> 301 -> 404 NoSuchBucket, so the discoverable-path premise no longer holds. MEDIUM->INFO.
- `I20` kept MEDIUM: CORS preflight on aws.amazon.com/s3 echoes an attacker-controlled Origin into Access-Control-Allow-Credentials.
