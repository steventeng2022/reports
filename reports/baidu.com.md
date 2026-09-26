# Security Audit Report — baidu.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://baidu.com/ |
| Bug bounty program | [Baidu](https://bsrc.baidu.com/v2/#/en) |
| Listed scope domain | baidu.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 6, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | low | C2 | Cookies set without Secure flag | CWE-614 |
| 3 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 4 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 5 | low | H4 | Missing X-Content-Type-Options: nosniff | CWE-693 |
| 6 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 7 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 8 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 9 | info | H2 | Short HSTS max-age | CWE-319 |
| 10 | info | H2b | HSTS without includeSubDomains | CWE-319 |
| 11 | info | H2c | HSTS not preloaded | CWE-319 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 14 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 15 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 16 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://baidu.com/ without HttpOnly: BAIDUID, BDSVRTM, BD_HOME, BIDUPSID, PSTM. Readable by client-side script.

### 2. [LOW] Cookies set without Secure flag (`C2`)

- **CWE:** CWE-614
- **Detail:** Set on https://baidu.com/ without Secure: BAIDUID, BDSVRTM, BD_HOME, BIDUPSID, PSTM. Will be transmitted over HTTP if the site is reachable cleartext.

### 3. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://baidu.com/ without SameSite=Lax/Strict: BAIDUID, BDSVRTM, BD_HOME, BIDUPSID, PSTM. Cross-site request cookies.

### 4. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://baidu.com/; no defense-in-depth against XSS/content injection.

### 5. [LOW] Missing X-Content-Type-Options: nosniff (`H4`)

- **CWE:** CWE-693
- **Detail:** No X-Content-Type-Options header on https://baidu.com/; browsers may MIME-sniff responses.

### 6. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://baidu.com/; page may be rendered in a foreign frame.

### 7. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for baidu.com lists 14 name(s) besides the scope host: baidu.cn, baidu.com.cn, w.baidu.com, ww.baidu.com, www.baidu.cn, www.baidu.com.cn, www.baidu.com.hk, www.baidu.hk... (1 no longer resolve)

### 8. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `wwww.baidu.com.cn` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 9. [INFO] Short HSTS max-age (`H2`)

- **CWE:** CWE-319
- **Detail:** HSTS max-age=172800 (< 1 year): `max-age=172800`.

### 10. [INFO] HSTS without includeSubDomains (`H2b`)

- **CWE:** CWE-319
- **Detail:** `max-age=172800` does not cover subdomains.

### 11. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=172800` lacks the preload directive.

### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header on https://baidu.com/; full URL (incl. query strings) is sent as referrer by default.

### 13. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://baidu.com/; browser features (camera, mic, geolocation) unrestricted.

### 14. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://baidu.com/ -> https://www.baidu.com/ (positive check).

### 15. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://baidu.com/ exposes 10 unique Disallow path(s) (/, /baidu, /bh, /cpro, /home/news/data/)

### 16. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on baidu.com.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://baidu.com/ final status: 200 (final URL https://www.baidu.com/).
- http://baidu.com/ initial status: 301.
- Certificate: DigiCert, Inc. DigiCert Secure Site Pro G2 TLS CN RSA4096 SHA256 2022 CA1, valid until 2027-03-03T23:59:59+00:00.
