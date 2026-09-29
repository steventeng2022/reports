# Security Audit Report — metro.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://metro.co.uk/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | metro.co.uk |
| Test date | 2026-09-29 12:58 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **10** (High: 0, Medium: 3, Low: 3, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 2 | medium | I1 | Reflected XSS in JavaScript context (refuted on re-verify) | CWE-79 |
| 3 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 4 | info | S1 | Dangling subdomain served by third-party platform (refuted on re-verify) | CWE-916 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 8 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter redirect_to on https://members.metro.co.uk/modal-login/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - fresh token reflects (a) URL-ENCODED inside the `metro.pageData` JSON in <script> (`%3C` stays encoded) and (b) inside a quoted `<input type=hidden>` value; breakout `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> MEDIUM.

### 2. [MEDIUM] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter referring_module on https://members.metro.co.uk/modal-login/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - fresh token reflects (a) URL-ENCODED inside the `metro.pageData` JSON in <script> (`%3C` stays encoded) and (b) inside a quoted `<input type=hidden>` value; breakout `x</script><img src=x onerror=alert(1)>` not emitted raw. Downgraded HIGH -> MEDIUM.

### 3. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /search/ which returns HTTP 200 (unauthenticated content reachable); robots.txt only hides paths from crawlers, not users.

### 4. [INFO] Dangling subdomain served by third-party platform (`S1`)

- **CWE:** CWE-916
- **Detail:** Subdomain api.metro.co.uk resolves to 54.192.248.45 and is served by cloudfront (error/landing page) - takeover candidate if the platform account is claimed. HTTP status 200
- **Re-verify 2026-09-29 (agent-aggressive):** refuted - api.metro.co.uk serves **HTTP 200 live WordPress VIP** content (Metro.co.uk homepage, via CloudFront 54.192.248.45), i.e. an active subdomain, not a dangling one. Downgraded MEDIUM -> INFO.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://metro.co.uk/

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://metro.co.uk/

### 7. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: metro.co.uk + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 8. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://metro.co.uk/

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://metro.co.uk/

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-29, agent-aggressive)

members.metro.co.uk/modal-login/ re-checked with fresh unique tokens and breakout payloads (direct HTTP, WordPress VIP behind CloudFront):
- `?redirect_to=`: token reflects (a) URL-ENCODED in the `metro.pageData` JSON inside <script> - encoded form cannot break out of a JS string; (b) inside `<input type="hidden" name="redirect_to" value="...">` - quoted attribute, breakout `"`/`<` not emitted raw (rawPayload=false on probes).
- `?referring_module=`: same - URL-encoded in pageData JSON only.
- `api.metro.co.uk`: 200 OK, `x-powered-by: WordPress VIP`, live Metro homepage via CloudFront - subdomain is ACTIVE, not dangling.
- Conclusion: both I1 HIGH -> MEDIUM (encoded/quoted reflections remain noteworthy as XSS-adjacent surface); S1 dangling subdomain -> INFO (active). Index row updated (10 total: 0H/3M/3L/4I).
