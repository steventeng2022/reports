# Security Audit Report — twitch.tv

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://twitch.tv/ |
| Bug bounty program | Twitch |
| Listed scope domain | twitch.tv |
| Test date | 2026-09-29 13:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 2, Low: 6, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 2 | low | S1 | Subdomain on live S3 marketing page (stale public stack: jQuery 3.3.1, React 16.3.2) | CWE-916 |
| 3 | medium | S1 | Live AWS ALB (awselb/2.0) serving empty 404 on all paths - abandoned API surface, takeover candidate | CWE-916 |
| 4 | low | S1 | Subdomain delegated to Atlassian Statuspage (stspg-customer.com), currently 503 | CWE-916 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | C1 | Cookies without Secure flag | CWE-614 |
| 7 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 8 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /login which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 2. [LOW] Subdomain on live S3 marketing page (stale public stack) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain dev.twitch.tv resolves to 65.9.185.41 (CloudFront) and serves a live 200 marketing page from AmazonS3 (42389B, "Home | Twitch Developers", cert valid to 2027). NOT dangling - re-verified live; downgraded MEDIUM->LOW. Public page loads stale libraries from CDN: jQuery 3.3.1 (<3.5.0, CVE-2020-11023) and React/ReactDOM 16.3.2 (2019). No forms/inputs on the page, limiting client-side injection surface.
- **Re-verify (2026-09-29, agent-aggressive):** GET https://dev.twitch.tv/ => 200, server=AmazonS3, len=42389, title="Home | Twitch Developers"; jquery-3.3.1.min.js loads (len=86927, "jQuery v3.3.1").

### 3. [MEDIUM] Live AWS ALB with no routes - abandoned API surface, takeover candidate (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.twitch.tv resolves to 54.192.248.126 and is served by an AWS Application Load Balancer (server=awselb/2.0). All probed paths (/, /favicon.ico, /graphql, /healthz, /api/) return HTTP 404 with an empty body: the ALB exists but has no target group/routes, i.e. an abandoned API front-end. TLS cert CN=api.twitch.tv is valid to 2027 (actively maintained). Takeover-able if the ALB is deregistered and the CNAME left dangling.
- **Re-verify (2026-09-29, agent-aggressive):** 5 paths all => 404 len=0 server=awselb/2.0; cert valid to 2027. Kept MEDIUM (live ALB, not a dangling CNAME).

### 4. [LOW] Subdomain delegated to Atlassian Statuspage (currently 503) (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain status.twitch.tv resolves to 3.169.121.117 via CNAME yfj40zdsk34s.stspg-customer.com (Atlassian Statuspage customer domain). Served by AtlassianEdge, currently returns HTTP 503 with Atlassian's default "Error 503 - Blast the tumbeasts!" page - the delegated status page is down but the third-party delegation itself is live (not dangling). Takeover-able only if the Statuspage customer account is abandoned.
- **Re-verify (2026-09-29, agent-aggressive):** GET https://status.twitch.tv/ => 503 len=17475 server=AtlassianEdge, title "Error 503 - Blast the tumbeasts!"; CNAME -> yfj40zdsk34s.stspg-customer.com. Downgraded MEDIUM->LOW (live delegation, page down).

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.twitch.tv/

### 6. [LOW] Cookies without Secure flag (`C1`)

- **CWE:** CWE-614
- **Detail:** twitch.lohp.countryCode set without Secure on https://www.twitch.tv/

### 7. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** server_session_id, unique_id, twitch.lohp.countryCode set without HttpOnly on https://www.twitch.tv/

### 8. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: twitch.tv + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.twitch.tv/

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-29, agent-aggressive)

All three S1 subdomains re-tested with a bare HTTP client + DNS + TLS cert inspection:

| Subdomain | Result | Verdict |
|---|---|---|
| dev.twitch.tv | 200 AmazonS3 live marketing page (42KB), jQuery 3.3.1 + React 16.3.2, cert to 2027 | live S3 page - MEDIUM->LOW (stale-stack note) |
| api.twitch.tv | 404 empty on 5/5 paths, server=awselb/2.0, cert CN=api.twitch.tv to 2027 | live ALB, no routes - kept MEDIUM (takeover candidate if ALB deleted) |
| status.twitch.tv | CNAME -> yfj40zdsk34s.stspg-customer.com; 503 AtlassianEdge default error page | live Atlassian Statuspage delegation, page down - MEDIUM->LOW |

None of the three is a dangling/no-origin subdomain; the original blanket "dangling third-party platform" wording was replaced with per-subdomain verdicts.
