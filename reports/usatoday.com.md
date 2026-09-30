# Security Audit Report — usatoday.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://usatoday.com/ |
| Bug bounty program | USA Today |
| Listed scope domain | usatoday.com |
| Test date | 2026-09-30 03:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 2, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H4 | No clickjacking protection | CWE-1023 |
| 2 | info | T2 | TLS certificate expiring within 32 days | CWE-295 |
| 3 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | I26 | security.txt exposed (public vulnerability disclosure policy) | CWE-200 |
| 6 | info | S1 | home 403 (425 B) bot wall with no Server header | CWE-916 |
| 7 | info | S1 | Varnish catch-all: 40+ subdomains 301 -> www (x-cache HIT); static 301 -> /errors/404/ | CWE-916 |
| 8 | low | S1 | Live first-party subdomains (account 200, chat 200 Gannett Customer Service Chat, help 200; login 406) | CWE-916 |
| 9 | info | S1 | api 404 (21 B); shop 301 -> usatodaystore.com/p/usa-today (UTM parameters) | CWE-916 |

## Detailed findings

### 1. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://usatoday.com/

### 2. [INFO] TLS certificate expiring within 32 days (`T2`)

- **CWE:** CWE-295
- **Detail:** Certificate for usatoday.com (CN=usatoday.com) valid_to Oct 31 06:54:24 2026 GMT.

### 3. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://usatoday.com/

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://usatoday.com/

### 5. [INFO] security.txt exposed (public vulnerability disclosure policy) (`I26`)

- **CWE:** CWE-200
- **Detail:** GET https://usatoday.com/.well-known/security.txt returned 200 (346 bytes) with a matching signature.
### 6. [INFO] home 403 (425 B) bot wall with no Server header (`S1`)

- **CWE:** CWE-916
- **Detail:** The apex returns 403 (425 B, "403 Forbidden") with no Server header for the probe client - a bot wall; browsers succeed.
- **Recommendation:** Expected edge filtering; document for future audits.

### 7. [INFO] Varnish catch-all: 40+ subdomains 301 -> www (x-cache HIT); static 301 -> /errors/404/ (`S1`)

- **CWE:** CWE-916
- **Detail:** 40+ probed subdomains 301 to www through the Varnish edge (x-cache HIT); static 301s to /errors/404/ - a single first-party catch-all.
- **Recommendation:** No dangling subdomains found; catch-all is first-party.

### 8. [LOW] Live first-party subdomains (account 200, chat 200 Gannett Customer Service Chat, help 200; login 406) (`S1`)

- **CWE:** CWE-916
- **Detail:** account 200 (2,349 B); chat 200 (19,512 B, "Gannett Customer Service Chat"); help 200 (32,476 B); login 406 (0 B). Live first-party service subdomains.
- **Recommendation:** Track the Gannett chat origin (shared news-group platform).

### 9. [INFO] api 404 (21 B); shop 301 -> usatodaystore.com/p/usa-today (UTM parameters) (`S1`)

- **CWE:** CWE-916
- **Detail:** api 404s with a 21 B body; shop 301s to the external storefront usatodaystore.com with UTM tracking parameters.
- **Recommendation:** The external storefront handoff carries UTM params - note for referrer hygiene.

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 x4:** home 403 (425 B bot wall, no Server header); 40+ subs 301 -> www Varnish catch-all (x-cache HIT); static 301 -> /errors/404/; account 200 (2,349 B), chat 200 (19,512 B Gannett CS chat), help 200 (32,476 B), login 406 (0 B); api 404 (21 B); shop 301 -> usatodaystore.com (UTM) (probe-r35e-subs).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
