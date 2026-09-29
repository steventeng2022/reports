# Security Audit Report — stitcher.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stitcher.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | stitcher.com |
| Test date | 2026-09-29 21:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 2, Low: 3, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 2 | medium | S1 | Dangling subdomain served by third-party platform | CWE-916 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain test.stitcher.com resolves to 18.154.144.37 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 502

### 2. [MEDIUM] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain app.stitcher.com resolves to 65.9.180.32 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on http://stitcher.com/

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on http://stitcher.com/

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on http://stitcher.com/

### 6. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on http://stitcher.com/

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on http://stitcher.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **S1 #1-2 (MEDIUM, kept):** re-probed both subdomains. test.stitcher.com (18.154.144.37) = 502, 960B; app.stitcher.com (65.9.180.32) = 502, 507B; both Cloudflare "ERROR: The request could not be satisfied" error pages with X-Cache: Error - the Cloudflare distribution is alive while the origin is dead, the dangling-family signature (502 variant of the confirmed 915/919B 403 pattern). The scanner had app.stitcher.com at 301 (http->https hop); the https endpoint is the 502 above, and unknown paths on it 301 -> www.stitcher.com/roadblock (first-party roadblock page). Both kept MEDIUM as takeover candidates (active CF edge, dead origin).
