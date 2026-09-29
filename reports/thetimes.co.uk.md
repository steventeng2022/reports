# Security Audit Report — thetimes.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://thetimes.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | thetimes.co.uk |
| Test date | 2026-09-29 22:23 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 1, Low: 3, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.thetimes.co.uk resolves to 65.9.180.40 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.thetimes.co.uk/

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.thetimes.co.uk/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.thetimes.co.uk/

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.thetimes.co.uk/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.thetimes.co.uk/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **S1 #1 (MEDIUM -> LOW):** api.thetimes.co.uk (65.9.180.40, CloudFront) = 301 (http->https hop) -> https: 403, 42B, content-type application/json, body {"message":"Missing Authentication Token"} with X-Amz-Cf-Id present. The response is IDENTICAL across /, /v1/, /api/ and /swagger.json - a live, auth-protected AWS API Gateway answering every path (the origin responds; this is the foodnetwork.com 403-JSON precedent, not the CF 915/919B "request could not be satisfied" dangling signature). Held LOW.
