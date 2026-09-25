# Security Audit Report — quora.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://quora.com/ |
| Bug bounty program | [Quora](https://hackerone.com/quora) |
| Listed scope domain | quora.com |
| Test date | 2026-09-25 04:28 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 3 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 6 | info | R1 | robots.txt discloses crawl rules/paths | CWE-200 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 8 | info | X2 | HTTPS homepage returned HTTP 403 | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on https://quora.com/. Clients may connect over plain HTTP on first visit.

### 2. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for quora.com lists 10 name(s) besides the scope host: *.cf2.quoracdn.net, *.fs.quoracdn.net, *.qr.ae, *.quora.com, *.tch.quora.com, *.tch.www.quora.com, *.www.quora.com, cf2.quoracdn.net... (2 no longer resolve)

### 3. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `cf2.quoracdn.net` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `fs.quoracdn.net` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://quora.com/ -> https://quora.com/ (positive check).

### 6. [INFO] robots.txt discloses crawl rules/paths (`R1`)

- **CWE:** CWE-200
- **Detail:** robots.txt on https://quora.com/ exposes 66 unique Disallow path(s) (*/answer/, */answers/, */unanswered/*, /, /*/@async)

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on quora.com.

### 8. [INFO] HTTPS homepage returned HTTP 403 (`X2`)

- **CWE:** CWE-200
- **Detail:** https://quora.com/ responded 403 (passive check only; no further probing).

## Reproduction notes

- Scanned 2026-09-25 04:28 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://quora.com/ final status: 403 (final URL https://www.quora.com/).
- http://quora.com/ initial status: 308.
- Certificate: Google Trust Services WR1, valid until 2026-10-27T06:08:45+00:00.
