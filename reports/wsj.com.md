# Security Audit Report — wsj.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wsj.com/ |
| Bug bounty program | The Wall Street Journal |
| Listed scope domain | wsj.com |
| Test date | 2026-09-29 14:46 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 4, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Subdomain is live SSO-protected app (CloudFront + Okta), not dangling | CWE-916 |
| 2 | low | S1 | Subdomain redirects to live third-party storefront, not dangling | CWE-916 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Subdomain is a live SSO-protected app (CloudFront + Okta SSO), not dangling (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain dev.wsj.com resolves to 54.192.248.4 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 2. [LOW] Subdomain redirects to a live third-party storefront, not dangling (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain shop.wsj.com resolves to 54.192.248.48 and is served by CloudFront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 301

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://wsj.com/

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://wsj.com/

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://wsj.com/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://wsj.com/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).


## Active re-verification (2026-09-29, agent-aggressive)

- shop.wsj.com: 301 -> **wsjshop.com** -> 200 (335 KB, Cloudflare) live storefront "The Wall Street Journal Shop" - active third-party commerce, not a dangling CloudFront landing. S1 #2 MEDIUM->LOW.
- dev.wsj.com: 301 -> www.dev.wsj.com -> 302 -> `/cf_site_auth/saml?returnTo=...` (CloudFront) -> 302 -> **newscorp.okta.com** SAML SSO (Okta app `newscorp_wsjdevdj_1`) -> 200 "News Corp - Sign In" (nginx) - a live SSO-protected developer portal, not dangling. S1 #1 MEDIUM->LOW.
