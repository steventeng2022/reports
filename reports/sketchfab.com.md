# Security Audit Report — sketchfab.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sketchfab.com/ |
| Bug bounty program | [Epic Games](https://hackerone.com/epicgames) |
| Listed scope domain | sketchfab.com |
| Test date | 2026-09-25 13:34 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 0, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 2 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 3 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for sketchfab.com lists 8 name(s) besides the scope host: *.sketchfab.me, api.sketchfab.com, blog.sketchfab.com, e6f79c614c67.sketchfab.com, sketchfab.me, skfb.ly, www.sketchfab.com, www.skfb.ly (1 no longer resolve)

### 2. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `e6f79c614c67.sketchfab.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 3. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://sketchfab.com/: ReadTimeout: HTTPSConnectionPool(host='sketchfab.com', port=443): Read timed out. (read timeout=15)

## Reproduction notes

- Scanned 2026-09-25 13:34 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://sketchfab.com/ initial status: 202.
- Certificate: Amazon Amazon RSA 2048 M04, valid until 2027-01-15T23:59:59+00:00.
