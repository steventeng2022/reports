# Security Audit Report — login.microsoftonline.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://login.microsoftonline.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | login.microsoftonline.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 3, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C3 | Cookies set without SameSite Lax/Strict | CWE-1004 |
| 2 | low | H3 | Missing Content-Security-Policy | CWE-79 |
| 3 | low | H6 | No clickjacking protection (X-Frame-Options / frame-ancestors) | CWE-1021 |
| 4 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 5 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 6 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 7 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 8 | info | H2c | HSTS not preloaded | CWE-319 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 11 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without SameSite Lax/Strict (`C3`)

- **CWE:** CWE-1004
- **Detail:** Set on https://login.microsoftonline.com/ without SameSite=Lax/Strict: esctx-fShpkHCGrtA, fpc, x-ms-gateway-slice. Cross-site request cookies.

### 2. [LOW] Missing Content-Security-Policy (`H3`)

- **CWE:** CWE-79
- **Detail:** No CSP header on https://login.microsoftonline.com/; no defense-in-depth against XSS/content injection.

### 3. [LOW] No clickjacking protection (X-Frame-Options / frame-ancestors) (`H6`)

- **CWE:** CWE-1021
- **Detail:** No X-Frame-Options and no CSP frame-ancestors on https://login.microsoftonline.com/; page may be rendered in a foreign frame.

### 4. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for login.microsoftonline.com lists 8 name(s) besides the scope host: login.microsoftonline-int.com, login.microsoftonline-p.com, login2.microsoftonline-int.com, login2.microsoftonline.com, loginex.microsoftonline-int.com, loginex.microsoftonline.com, stamp2.login.microsoftonline-int.com, stamp2.login.microsoftonline.com (5 no longer resolve)

### 5. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `login2.microsoftonline-int.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 6. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `login2.microsoftonline.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 7. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `loginex.microsoftonline-int.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 8. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://login.microsoftonline.com/; browser features (camera, mic, geolocation) unrestricted.

### 10. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://login.microsoftonline.com/ -> https://login.microsoftonline.com:443/ (positive check).

### 11. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on login.microsoftonline.com.

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://login.microsoftonline.com/ final status: 200 (final URL https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&response_mode=form_post&nonce=639259267768001581.NTI1Yzc2ZTAtNjg5ZC00MTA1LWFiZTUtMjU2OTcyMzJkNjEzMjJkYjRlYWYtNGQxMy00ZDNjLWI0YWMtMjJiYzEzN2IyMzZj&ui_locales=en-US&mkt=en-US&client-request-id=e4aecaf2-69b6-497e-a3aa-f5c97b293a70&siwa=1&siwg=1&state=P4KDpozs0GMNlcA4NUr2z-I438I_-yqZzyGQfXSS1KXyh9hSKRjD9NlfEbGvwjYdCwWrSJIEpAMG-60ESWYzfl4UCLYhbsCdJzG_-wHufSL_y3PiBYye1xTieRjdPMCzRgXr2GaAI9pFue9YwLy1LQBGKFkbXY2z9uqAT9AkOsGPCWTHBNswe_P7rwveYq_wrZZUQ18XRuoVIabtNh4KP2WNJ2B3butRdFodlAcCAIPgA2TuSylQesPDVKRm5vYPrC03RzX8FkN0pGCRzkLtlugb-8Z_XCBRcQ67PpgbQKK17SJiEdqaUXFXYW8YZRcalgXF1Jgaaq5We8fZCnlnRfwBA94NyoE8p6F1SN0jrXoqoPLvhgxPvADwFC1x1cU0coQUf-fUsMOGUbTklH-snMnP8Ltv99xaoBEuk4ON2lau2ecE-X55UwzEuLssyQSw&x-client-SKU=ID_NET8_0&x-client-ver=8.16.0.0).
- http://login.microsoftonline.com/ initial status: 302.
- Certificate: Microsoft Corporation Microsoft TLS G2 RSA CA OCSP 04, valid until 2026-11-21T00:37:12+00:00.
