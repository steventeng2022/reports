# Security Audit Report — bookstackapp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bookstackapp.com/ |
| Bug bounty program | None (open-source project; GitHub issue tracker) |
| Listed scope domain | bookstackapp.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 0, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | H2c | HSTS not preloaded | CWE-319 |
| 2 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 3 | info | M1 | sitemap.xml discloses URL inventory | CWE-200 |
| 4 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 5 | info | S2 | security.txt exposed (public disclosure policy) | CWE-200 |

## Detailed findings

### 1. [INFO] HSTS not preloaded (`H2c`)

- **CWE:** CWE-319
- **Detail:** `max-age=31536000; includeSubDomains` lacks the preload directive.

### 2. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://bookstackapp.com/; browser features (camera, mic, geolocation) unrestricted.

### 3. [INFO] sitemap.xml discloses URL inventory (`M1`)

- **CWE:** CWE-200
- **Detail:** sitemap.xml on https://bookstackapp.com/ lists 240 URLs.

### 4. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://bookstackapp.com/ -> https://bookstackapp.com/ (positive check).

### 5. [INFO] security.txt exposed (public disclosure policy) (`S2`)

- **CWE:** CWE-200
- **Detail:** security.txt present on https://bookstackapp.com (203 bytes); contact: https://www.bookstackapp.com/links/contact/

## Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://bookstackapp.com/ final status: 200 (final URL https://www.bookstackapp.com/).
- http://bookstackapp.com/ initial status: 308.
- Certificate: Let's Encrypt YE2, valid until 2026-11-22T01:27:08+00:00.

## Active agent cross-check (deep-dive scan on main - bookstackapp.com)

Total findings: **12** - BookStack v26 deep-dive by agent-deepdive (main branch): fresh-DDL install bugs + permission model. Full detailed findings remain in the main-branch version of this file; passive re-audit above is the non-injection view.

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | high | F3a-id | Fresh install: creating a book fails — entities.id NOT NULL without autoincrement | CWE-552 |
| 2 | high | F3a-slug | Fresh install: creating a page fails — entities.slug NOT NULL without default | CWE-552 |
| 3 | high | F3e | Fresh install: container creation fails — entity_container_data.description NOT NULL without default | CWE-552 |
| 4 | high | F3d | Fresh install: page save fails — entity_page_data.revision_count NOT NULL without default | CWE-552 |
| 5 | medium | F1 | Broken access control on trashed pages: image edit/rename/replace/delete allowed with only global image permissions | CWE-284 |
| 6 | medium | F1c | Anonymous access to /uploads/images/{path} files (no auth middleware), including orphaned files from trashed pages | CWE-284 |
| 7 | medium | F3c | Original DatabaseTransaction issues MySQL-only isolation SQL — 500 on SQLite (officially supported DB) | CWE-552 |
| 8 | medium | F7 | Attachment upload fails on shipped 2016 schema — attachments.external NOT NULL without default | CWE-552 |
| 9 | low | F1b | Drawio XML readable via /images/drawio/base64 with only page-view-all (no drawio permission) | CWE-284 |
| 10 | low | F2 | GET /images/gallery and /images/drawio without uploaded_to param → unhandled TypeError, HTTP 500 | CWE-754 |
| 11 | low | F2b | Attachment edit/update/upload on trashed parent page → unhandled 500 | CWE-754 |
| 12 | low | F4 | CSRF: X-XSRF-TOKEN header must be URL-decoded; raw cookie value always 419 (state-changing API clients break) | CWE-352 |
