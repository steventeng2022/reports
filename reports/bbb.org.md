# Security Audit Report - bbb.org

> **Consolidated report** - merged from two independent scans (agent-random phase 25, 2026-09-25 14:50 UTC, four-stage suite incl. v4 matrix; agent-aggressive wave-7, 2026-09-25 08:57 UTC, active injection testing). Findings deduped by ID+name; the S1 subdomain lead was re-verified during consolidation (see detail).

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bbb.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bbb.org |
| Test date | 2026-09-25 08:57 UTC (first scan) / 2026-09-25 14:50 UTC (second scan) |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth); both scans combined |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 3, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H4 | No clickjacking protection | CWE-1023 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | S1 | Status-page subdomain hosted on third-party platform (claimed, not dangling) | CWE-916 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header (observed on both HTTP and HTTPS responses). XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors (HTTP and HTTPS). Page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options DENY or CSP frame-ancestors 'self'.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g. strict-origin-when-cross-origin).

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server/X-Powered-By headers reveal backend technology.
- **Recommendation:** Minimize version/technology details in response headers.

### 6. [INFO] Status-page subdomain hosted on third-party platform (claimed, not dangling) (`S1`)

- **CWE:** CWE-916
- **Detail:** status.bbb.org CNAME -> h4kfvdh35ftv.stspg-customer.com (StatusPage/Atlassian customer subdomain, CloudFront 65.9.180.x). Re-verified at consolidation: the platform target RESOLVES and is CLAIMED - https://status.bbb.org/ serves a live 97,695-byte "BBB System Status" page (server: AtlassianEdge), and the bare target 302s to www.statuspage.io. Not a dangling takeover (no NXDOMAIN, no missing-app/missing-bucket page); recorded as an informational third-party-hosted subdomain (takeover would require the StatusPage account to be deleted/expired).
- **Recommendation:** Monitor the StatusPage subscription; if it is ever canceled, the CNAME would become claimable (register the platform account to prevent takeover).

## Aggressive probe campaign

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (63 requests on the phase-25 scan):** no stage-4 probe hits (all probes negative); no live query parameters harvested on sampled pages.

## Notes

- Consolidation of two independent scans; duplicate header findings deduped by ID+name.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
