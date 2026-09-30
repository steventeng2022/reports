# Security Audit Report — mozilla.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://mozilla.org/ |
| Bug bounty program | Mozilla |
| Listed scope domain | mozilla.org |
| Test date | 2026-09-29 15:48 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H4 | No clickjacking protection | CWE-1023 |
| 3 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | low | S1 | Live first-party subdomains incl. ftp directory listing (/pub/) and Element/Matrix chat | CWE-916 |
| 7 | info | S1 | Subdomain redirect surface to first-party destinations | CWE-916 |
| 8 | info | S1 | vpn.mozilla.org = 406 (0 B) | CWE-916 |
| 9 | info | S1 | apex mozilla.org = 302 -> www (granian origin) | CWE-916 |
| 10 | info | S1 | 13 probed subdomains NXDOMAIN (admin/staging/api/mail/docs/portal/sandbox/internal/legacy/old/app/sso/oauth) | CWE-916 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://mozilla.org/

### 2. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://mozilla.org/

### 3. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://mozilla.org/

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://mozilla.org/

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx
### 6. [LOW] Live first-party subdomains incl. ftp directory listing (/pub/) and Element/Matrix chat (`S1`)

- **CWE:** CWE-916
- **Detail:** ftp.mozilla.org = 200 (1,600 B, plain "Index of /" directory listing exposing /pub/); chat.mozilla.org = 200 (4,721 B, title "Element", Matrix-based team chat); support.mozilla.org = 200 (3,038 B, Cloudflare Client Challenge page). All first-party (probe-r35e-subs).
- **Recommendation:** Review the ftp /pub/ listing exposure and the public Element origin.

### 7. [INFO] Subdomain redirect surface to first-party destinations (`S1`)

- **CWE:** CWE-916
- **Detail:** dev 301 -> developer.mozilla.org; git 302 -> wiki.mozilla.org/DeveloperServices/HistoricalVCS; beta 301 -> /firefox/channel/#beta; status 302 -> www; store/download 302 -> www; blog 301 -> blog.mozilla.org/en/ (Cloudflare). All first-party destinations.
- **Recommendation:** Document the redirect map; no external destinations observed.

### 8. [INFO] vpn.mozilla.org = 406 (0 B) (`S1`)

- **CWE:** CWE-916
- **Detail:** vpn.mozilla.org returns 406 Not Acceptable (0 B) to the probe client - a first-party VPN/edge endpoint with an unusual status.
- **Recommendation:** Confirm the 406 is intentional client filtering.

### 9. [INFO] apex mozilla.org = 302 -> www (granian origin) (`S1`)

- **CWE:** CWE-916
- **Detail:** The apex 302s to www with a granian (Rust) origin server signature in the hop chain.
- **Recommendation:** Note the granian origin for fingerprinting reference.

### 10. [INFO] 13 probed subdomains NXDOMAIN (admin/staging/api/mail/docs/portal/sandbox/internal/legacy/old/app/sso/oauth) (`S1`)

- **CWE:** CWE-916
- **Detail:** admin, staging, api, mail, docs, portal, sandbox, internal, legacy, old, app, sso, oauth subdomains all NXDOMAIN - no dangling DNS for these high-value names.
- **Recommendation:** Recheck after the next DNS sweep.

## Active re-verification (2026-09-30, agent-aggressive)

- **S1 x5:** ftp 200 (1,600 B "Index of /" exposing /pub/), chat 200 (4,721 B Element/Matrix), support 200 (3,038 B CF challenge); dev/git/beta/status/store/download/blog -> first-party destinations; vpn 406 (0 B); apex 302 -> www (granian); 13 subs NXDOMAIN (probe-r35e-subs).

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
