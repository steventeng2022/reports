# Security Audit Report — docker.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://docker.com/ |
| Bug bounty program | Docker |
| Listed scope domain | docker.com |
| Test date | 2026-09-25 04:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 1, Low: 6, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | S1 | test.docker.com - live S3 (Docker install script) on retest | CWE-916 |
| 3 | low | S1 | beta.docker.com - 301 to www.docker.com on retest | CWE-916 |
| 4 | low | S1 | status.docker.com - 301 to dockerstatus.com on retest | CWE-916 |
| 5 | low | S1 | docs.docker.com - live S3 (Docker Docs) on retest | CWE-916 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | T2 | TLS certificate expiring within 34 days | CWE-295 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /pricing/contact-sales/bss-cc-thankyou/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] test.docker.com - live S3 (Docker install script) on retest (`S1`)

- **CWE:** CWE-916
- **Detail:** test.docker.com -> 54.192.248.27. RETEST 2026-09-25: 200 from AmazonS3 (via CloudFront) serving the Docker Engine for Linux install script (23KB shell script). LIVE managed content, not a dangling platform account. Downgraded medium -> low.

### 3. [LOW] beta.docker.com - 301 to www.docker.com on retest (`S1`)

- **CWE:** CWE-916
- **Detail:** beta.docker.com. RETEST 2026-09-25: 301 (AmazonS3 via CloudFront) -> https://www.docker.com/. Managed redirect, not dangling. Downgraded medium -> low.

### 4. [LOW] status.docker.com - 301 to dockerstatus.com on retest (`S1`)

- **CWE:** CWE-916
- **Detail:** status.docker.com. RETEST 2026-09-25: 301 (AmazonS3 via CloudFront) -> https://dockerstatus.com/ (their Statuspage). Managed redirect, not dangling. Downgraded medium -> low.

### 5. [LOW] docs.docker.com - live S3 (Docker Docs) on retest (`S1`)

- **CWE:** CWE-916
- **Detail:** docs.docker.com. RETEST 2026-09-25: 200 from AmazonS3 serving "Docker Docs" (187KB). LIVE managed content, not dangling. Downgraded medium -> low.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.docker.com/

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: docker.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] TLS certificate expiring within 34 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for www.docker.com (CN=docker.com) valid_to Oct 28 10:32:23 2026 GMT.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
