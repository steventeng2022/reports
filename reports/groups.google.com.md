# Security Audit Report — groups.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://groups.google.com/ |
| Bug bounty program | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| Listed scope domain | groups.google.com |
| Test date | 2026-09-25 00:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 0, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | H2c | HSTS not preloaded | CWE-319 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 6 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 7 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for groups.google.com lists 65 name(s) besides the scope host: *.aistudio.google.com, *.android.com, *.appengine.google.com, *.bdn.dev, *.cloud.google.com, *.crowdsource.google.com, *.datacompute.google.com, *.flash.android.com...

### 2. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://groups.google.com/; full URL (incl. query strings) is sent as referrer by default.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://groups.google.com/ -> https://groups.google.com/ (positive check).

### 5. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://groups.google.com/ exposes 17 unique Disallow path(s) (/, /*_escaped_fragment_=aboutgroup, /*_escaped_fragment_=forumsearch, /*_escaped_fragment_=myforums, /*_escaped_fragment_=newtopic) and 1 sitemap reference(s)

### 6. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on groups.google.com.

### 7. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://groups.google.com/ redirects to https://accounts.google.com/v3/signin/identifier?continue=https://groups.google.com/&followup=https://groups.google.com/&osid=1&passive=1209600&flowName=GlifWebSignIn&flowEntry=ServiceLogin&dsh=S-1761314323:1790297162583889.

## Reproduction notes

- Scanned 2026-09-25 00:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://groups.google.com/ final status: 200 (final URL https://accounts.google.com/v3/signin/identifier?continue=https://groups.google.com/&followup=https://groups.google.com/&osid=1&passive=1209600&flowName=GlifWebSignIn&flowEntry=ServiceLogin&dsh=S-1761314323:1790297162583889).
- http://groups.google.com/ initial status: 301.
- Certificate: Google Trust Services WE2, valid until 2026-12-03T19:22:00+00:00.
