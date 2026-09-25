# Security Audit Report — aws.amazon.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aws.amazon.com/ |
| Bug bounty program | [Amazon](https://hackerone.com/amazonvrp) |
| Listed scope domain | aws.amazon.com |
| Test date | 2026-09-25 15:44 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | H2c | HSTS not preloaded | CWE-319 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 12 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 13 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://aws.amazon.com/ without HttpOnly: aws-priv, aws_lang. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://aws.amazon.com/ without Secure: aws_lang. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://aws.amazon.com/ without SameSite=Lax/Strict: aws-priv, aws_lang. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://aws.amazon.com/; no defense-in-depth against XSS/content injection.

### 5. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for aws.amazon.com lists 6 name(s) besides the scope host: 1.aws-lbr.amazonaws.com, amazonaws-china.com, aws-us-east-1.amazon.com, aws-us-west-2.amazon.com, www.amazonaws-china.com, www.aws.amazon.com (2 no longer resolve)

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `1.aws-lbr.amazonaws.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `aws-us-west-2.amazon.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 8. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=47304000; includeSubDomains` lacks the preload directive.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://aws.amazon.com/; full URL (incl. query strings) is sent as referrer by default.

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://aws.amazon.com/; browser features (camera, mic, geolocation) unrestricted.

### 11. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://aws.amazon.com/ -> https://aws.amazon.com/ (positive check).

### 12. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://aws.amazon.com/ exposes 262 unique Disallow path(s) (*/confirmation/, */registration-confirmation/, /*/blogs/, /*/blogs/*/tag/, /*/community/heroes/) and 3 sitemap reference(s)

### 13. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://aws.amazon.com (575 bytes); contact: mailto:aws-security@amazon.com

## Reproduction notes

- Scanned 2026-09-25 15:44 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://aws.amazon.com/ final status: 200 (final URL https://aws.amazon.com/).
- http://aws.amazon.com/ initial status: 301.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-03-04T23:59:59+00:00.
