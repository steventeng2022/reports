# Security Audit Report — politico.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://politico.com/ |
| Bug bounty program | Politico |
| Listed scope domain | politico.com |
| Test date | 2026-09-29 13:19 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | low | I1 | Reflected token in JavaScript context (Cloudflare challenge boundary) | CWE-79 |
| 7 | info | S1 | home 403 (5,726 B) challenge; login 200 (4,508 B); auth 302 -> auth.politico.com/login; api 401 (0 B); images 403 (263 B); static 404 (365 B) | CWE-916 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://politico.com/

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://politico.com/

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://politico.com/

### 4. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://politico.com/

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://politico.com/
### 6. [LOW] Reflected token in JavaScript context (Cloudflare challenge boundary) (`I1`)

- **CWE:** CWE-79
- **Detail:** GET /?ray=Zx7qK2v9Bm -> 403 (5,722 B, Cloudflare managed challenge "Just a moment..."); the token reflects at index 2706 inside cUPMDTk:"/?ray=Zx7qK2v9Bm\u0026__cf_chl_tk=..." (& encoded as \u0026); quote probe re-encoded to %22 (re-verified live 2026-09-30). No breakout from the challenge script context.
- **Recommendation:** Keep the challenge token inside the encoded cUPMDTk string; watch for future CF template changes.

### 7. [INFO] home 403 (5,726 B) challenge; login 200 (4,508 B); auth 302 -> auth.politico.com/login; api 401 (0 B); images 403 (263 B); static 404 (365 B) (`S1`)

- **CWE:** CWE-916
- **Detail:** The apex 403s with the CF challenge (5,726 B); login 200 (4,508 B); auth 302s to the first-party auth subdomain; api 401 (0 B); images 403 (263 B); static 404 (365 B).
- **Recommendation:** All first-party; the auth subdomain is the identity entry point.

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x1:** /?ray= = 403 (5,722 B CF managed challenge); token at idx 2706 in cUPMDTk JSON (& as \u0026); " probe -> %22 (re-verified 2026-09-30); no breakout.
- **S1 x1:** home 403 (5,726 B); login 200 (4,508 B); auth 302 -> auth.politico.com/login; api 401 (0 B); images 403 (263 B); static 404 (365 B).

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
