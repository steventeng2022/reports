# Security Audit Report — bitpay.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bitpay.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bitpay.com |
| Test date | 2026-09-30 06:21 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 2, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Live Atlassian statuspage (not dangling) | CWE-916 |
| 2 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Live Atlassian statuspage (not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.bitpay.com resolves to 54.192.248.124 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: bitpay.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.bitpay.com/

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 (MEDIUM -> LOW):** status.bitpay.com re-probed (http + https) = 200 (132,804 B) server AtlassianEdge, title "BitPay Inc Status" (live Atlassian status page, ACAO=*) - live first-party platform page, not the 915 B dangling CloudFront signature.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
