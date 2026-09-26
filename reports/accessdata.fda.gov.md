# Security Audit Report — accessdata.fda.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://accessdata.fda.gov/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | accessdata.fda.gov |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **2** (High: 0, Medium: 0, Low: 0, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | T0 | TLS handshake could not be completed | CWE-200 |
| 2 | info | X1 | HTTPS homepage unreachable | CWE-200 |

## Detailed findings

### 1. [INFO] TLS handshake could not be completed (`T0`)

- **CWE:** CWE-200
- **Detail:** No TLS version completed a handshake on accessdata.fda.gov:443 (versions: {'TLSv1.0': False, 'TLSv1.1': False, 'TLSv1.2': False, 'TLSv1.3': False}; errors: ['TLSv1.0: [SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1010)', 'TLSv1.1: [SSL: NO_PROTOCOLS_AVAILABLE] no protocols available (_ssl.c:1010)']).

### 2. [INFO] HTTPS homepage unreachable (`X1`)

- **CWE:** CWE-200
- **Detail:** https://accessdata.fda.gov/: ConnectionError: ('Connection aborted.', ConnectionResetError(10054, '遠端主機已強制關閉一個現存的連線。', None, 10054, None))

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- http://accessdata.fda.gov/ initial status: 400.

## Active agent cross-check (phase 25 aggressive scan on main - accessdata.fda.gov)

Total findings: **7** - latest aggressive-method scan (main branch). Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | R2 | No HTTP->HTTPS redirect | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
