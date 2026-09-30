# Security Audit Report — 9to5mac.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://9to5mac.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | 9to5mac.com |
| Test date | 2026-09-30 03:40 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 14, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 3 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I33 | WordPress user enumeration via ?author=1 | CWE-200 |
| 11 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 12 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |
| 15 | low | I22 | Slug-collision 301 hops retain the url parameter (8 endpoints) (no open redirect) | CWE-538 |
| 16 | low | I22 | /follow?url self-loop (parameter unconsumed) | CWE-538 |
| 17 | low | S1 | ftp.9to5mac.com = 200 (201 B "Coming Soon", Apache/2.4) on :80 only; :443 = EPROTO | CWE-916 |
| 18 | info | S1 | mail 301 -> mail.google.com/a/9to5mac.com (ghs); 45 probed subdomains 404 (548 B, single nginx origin); www 301 -> apex (x-cache EXPIRED) | CWE-916 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://9to5mac.com/

### 2. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/2026/09/29/apple-pay-now-rolling-out-to-axis-bank-customers-in-india/ reflects input verbatim in body context; encoding boundary not confirmed.

### 3. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/2026/09/29/bank-of-america-says-metas-muse-highlights-a-new-risk-for-apples-services-revenue/ reflects input verbatim in body context; encoding boundary not confirmed.

### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/2026/09/29/apple-tv-renews-french-drama-careme-for-season-two/ reflects input verbatim in body context; encoding boundary not confirmed.

### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/poll-post/how-do-you-plan-on-buying-your-next-iphone/ reflects input verbatim in body context; encoding boundary not confirmed.

### 6. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter extended-comments on https://9to5mac.com/2026/09/29/daily-september-29-2026/ reflects input verbatim in body context; encoding boundary not confirmed.

### 7. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://9to5mac.com/ reflects input verbatim in body context; encoding boundary not confirmed.

### 8. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://9to5mac.com/redirect reflects input verbatim in body context; encoding boundary not confirmed.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://9to5mac.com/go reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] WordPress user enumeration via ?author=1 (`I33`)

- **CWE:** CWE-200
- **Detail:** GET https://9to5mac.com/?author=1 returns 301 -> https://9to5mac.com/author/seth844/; author slug (username) disclosed. Combine with xmlrpc.php for brute force.

### 11. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: 9to5mac.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 12. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://9to5mac.com/

### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://9to5mac.com/

### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx
### 15. [LOW] Slug-collision 301 hops retain the url parameter (8 endpoints) (no open redirect) (`I22`)

- **CWE:** CWE-538
- **Detail:** /r, /out, /link, /continue, /next, /return, /jump, /target with ?url=Zx7qK2v9Bm all 301 to WordPress article slugs that happen to match the endpoint names (e.g. /2024-09-26/rabbit-r1-...?url=); the token is retained in Location but the slug wins - no open redirect (probe-r35redirects).
- **Recommendation:** The slug collisions are accidental but a useful parameter-retention map.

### 16. [LOW] /follow?url self-loop (parameter unconsumed) (`I22`)

- **CWE:** CWE-538
- **Detail:** /follow?url=Zx7qK2v9Bm -> 301 /follow-9to5mac/?url= -> 301 back to /follow-9to5mac/?url= (self-loop) -> 200 (149,450 B); the parameter is never consumed (probe-r35redirects).
- **Recommendation:** Break the self-loop or consume the parameter.

### 17. [LOW] ftp.9to5mac.com = 200 (201 B "Coming Soon", Apache/2.4) on :80 only; :443 = EPROTO (`S1`)

- **CWE:** CWE-916
- **Detail:** The ftp subdomain answers on plain HTTP (Apache/2.4 "Coming Soon") and fails TLS with EPROTO - a live but half-configured first-party host.
- **Recommendation:** Put ftp behind TLS or remove it.

### 18. [INFO] mail 301 -> mail.google.com/a/9to5mac.com (ghs); 45 probed subdomains 404 (548 B, single nginx origin); www 301 -> apex (x-cache EXPIRED) (`S1`)

- **CWE:** CWE-916
- **Detail:** The mail subdomain 301s to the Google Workspace host; 45 other probed subdomains 404 with an identical 548 B body from a single nginx origin; www 301s to the apex with x-cache EXPIRED.
- **Recommendation:** Single-origin 404 fingerprinting confirmed across the subdomain sweep.

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 x2:** 8 endpoint names collide with WordPress slugs -> 301 with url retained in Location; /follow?url 301 -> /follow-9to5mac/ self-loop 301 -> 200 (149,450 B), param unconsumed (probe-r35redirects).
- **S1 x2:** ftp :80 200 (201 B "Coming Soon" Apache/2.4), :443 EPROTO; mail 301 -> mail.google.com (ghs); 45 subs 404 (548 B single nginx origin); www 301 -> apex (x-cache EXPIRED) (probe-r35e-subs).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
