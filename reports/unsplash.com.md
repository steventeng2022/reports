# Security Audit Report — unsplash.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://unsplash.com/ |
| Bug bounty program | Unsplash |
| Listed scope domain | unsplash.com |
| Test date | 2026-09-30 04:59 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I22 | Public autocomplete endpoint from robots.txt (no hidden data) | CWE-538 |
| 2 | low | S1 | Live Atlassian statuspage (not dangling) | CWE-916 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Public autocomplete endpoint from robots.txt (no hidden data) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /nautocomplete which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Live Atlassian statuspage (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.unsplash.com resolves to 3.169.121.20 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://unsplash.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://unsplash.com/

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://unsplash.com/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://unsplash.com/

### 7. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://unsplash.com/.well-known/security.txt returned 200 (130 bytes) with a matching signature.

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 (MEDIUM -> LOW):** /nautocomplete re-probed = 200 (48 B) JSON {"fuzzy":[],"autocomplete":[],"did_you_mean":[]} - public autocomplete endpoint, no hidden data.
- **S1 (MEDIUM -> LOW):** status.unsplash.com re-probed = 200 (105,124 B) AtlassianEdge title "Unsplash Status" - live Atlassian statuspage, not dangling.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
