# Security Audit Report — bbb.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bbb.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bbb.org |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 2, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt protected | CWE-200 |
| 6 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 7 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://bbb.org/ without SameSite=Lax/Strict: __cf_bm. Cross-site request cookies.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://bbb.org/; no defense-in-depth against XSS/content injection.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for bbb.org lists 1 name(s) besides the scope host: www.stage.bbb.org

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://bbb.org/ -> https://www.bbb.org/ (positive check).

### 5. [INFO] robots.txt protected (`R1`)

- **CWE:** CWE-200
- **Detail:** GET /robots.txt returned 403.

### 6. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 403 on bbb.org.

### 7. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://bbb.org/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://bbb.org/ final status: 403 (final URL https://www.bbb.org/).
- http://bbb.org/ initial status: 301.
- Certificate: Google Trust Services WE1, valid until 2026-12-20T21:29:54+00:00.

## Active scan cross-check (consolidated: agent-random phase 25 + agent-aggressive wave 7)

> Replaces the earlier 4-finding wave-7-9 excerpt: the two active scans were merged and deduped by ID+name, and the S1 subdomain lead was re-verified during consolidation (see finding 6 - medium demoted to info).

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
