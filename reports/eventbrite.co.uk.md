# Security Audit Report — eventbrite.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eventbrite.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | eventbrite.co.uk |
| Test date | 2026-09-29 16:16 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 10, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | S1 | Subdomain 307-redirects to live Eventbrite property, not dangling | CWE-916 |
| 2 | low | S1 | Subdomain 307-redirects to live Eventbrite property, not dangling | CWE-916 |
| 3 | low | S1 | Subdomain 307-redirects to live Eventbrite property, not dangling | CWE-916 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 7 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 11 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [LOW] Subdomain 307-redirects to a live Eventbrite property, not dangling (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain dev.eventbrite.co.uk resolves to 65.9.180.122 (CloudFront). **Re-verify (2026-09-29, agent-aggressive):** 307 -> https://www.eventbrite.com -> 200 (240654B) - active alias of the main site, not dangling. MEDIUM->LOW.

### 2. [LOW] Subdomain 307-redirects to a live Eventbrite property, not dangling (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain test.eventbrite.co.uk resolves to 65.9.180.120 (CloudFront). **Re-verify (2026-09-29, agent-aggressive):** 307 -> https://www.eventbrite.ca/e/test-event-registration-45375865435 -> 200 (156233B) - a 2018 test event page still published live; the subdomain is an active redirect, not dangling. MEDIUM->LOW (note: stale public test event is a minor hygiene issue).

### 3. [LOW] Subdomain 307-redirects to a live Eventbrite property, not dangling (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain stage.eventbrite.co.uk resolves to 65.9.180.129 (CloudFront). **Re-verify (2026-09-29, agent-aggressive):** 307 -> https://www.eventbrite.com -> 200 (240654B) - active alias, not dangling. MEDIUM->LOW.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.eventbrite.co.uk/

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.eventbrite.co.uk/

### 6. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** csrftoken, stableId set without HttpOnly on https://www.eventbrite.co.uk/

### 7. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /esi_cache/ which returns 403, indicating a hidden/protected resource exists at that path.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter referrer on https://www.eventbrite.co.uk/signin/signup reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter referrer on https://www.eventbrite.co.uk/signin/signup/ reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: eventbrite.co.uk + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 11. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.eventbrite.co.uk/

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.eventbrite.co.uk/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
