# Security Audit Report — linktr.ee

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://linktr.ee/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | linktr.ee |
| Test date | 2026-09-25 12:02 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **5** (High: 0, Medium: 2, Low: 3, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | I11 | GraphQL introspection enabled on /api/graphql | CWE-200 |
| 5 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /s/about/trust-center/report which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.linktr.ee resolves to 54.192.248.30 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://linktr.ee/

### 4. [LOW] GraphQL introspection enabled on /api/graphql (`I11`)

- **CWE:** CWE-200
- **Detail:** POST https://linktr.ee/api/graphql with {__schema{types{name}}} returns the full type map.

### 5. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: linktr.ee + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Reproduction notes

- Scanned 2026-09-25 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
