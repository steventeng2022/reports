# Security Audit Report — guardian.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://guardian.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | guardian.co.uk |
| Test date | 2026-09-30 05:31 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 2, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies without Secure flag | CWE-614 |
| 2 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |

## Detailed findings

### 1. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** gu_client_ab_tests, gu_v2_mvt_id set without Secure on https://www.theguardian.com/

### 2. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** gu_client_ab_tests, gu_client_ab_tests, gu_v2_mvt_id, gu_v2_mvt_id, GU_mvt_id, GU_geo_country set without HttpOnly on https://www.theguardian.com/

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
