# Security Audit Report - harvard.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://harvard.edu |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | harvard.com
| Test date | 2026-09-30 10:17 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), redirect-path parameter propagation, subdomain enumeration, security-header and cookie audit; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 9, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | ver param reflects in JSON-LD @id (script context) | CWE-79 |
| 2 | low | I1 | id param reflects in JSON-LD @id (script context) | CWE-79 |
| 3 | low | I1 | w param reflects in JSON-LD url (script context) | CWE-79 |
| 4 | low | I1 | degree_levels param reflects in JSON-LD @id (script context) | CWE-79 |
| 5 | low | I1 | v param reflects in JSON-LD @id (script context) | CWE-79 |
| 6 | info | I22 | Hidden /r and /go paths 301 to first-party content pages with param retained | CWE-538 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | low | H1 | Missing HSTS header | CWE-319 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | S1 | test.harvard.edu 404 (Pantheon) | CWE-916 |
| 12 | low | S1 | login.harvard.edu Okta SSO with bookmark path | CWE-916 |

## Detailed findings

### 1. [LOW] ver param reflects in JSON-LD @id (script context) (I1)

- **CWE:** CWE-79
- **Detail:** ?ver=token reflects URL-encoded inside the <script> JSON-LD @id field; quote-breakout (quote payload) returns 301 with the token stripped (page 10 B shorter) - no raw quote breakout.

### 2. [LOW] id param reflects in JSON-LD @id (script context) (I1)

- **CWE:** CWE-79
- **Detail:** ?id=token reflects URL-encoded inside the <script> JSON-LD @id field; quote-breakout probe stripped - no raw quote breakout.

### 3. [LOW] w param reflects in JSON-LD url (script context) (I1)

- **CWE:** CWE-79
- **Detail:** ?w=token reflects inside a second JSON-LD document (Conferral of Degrees page, 114 KB); quote-breakout probe absent from response - no raw quote breakout.

### 4. [LOW] degree_levels param reflects in JSON-LD @id (script context) (I1)

- **CWE:** CWE-79
- **Detail:** ?degree_levels=token reflects URL-encoded inside the <script> JSON-LD @id field; quote-breakout probe stripped - no raw quote breakout.

### 5. [LOW] v param reflects in JSON-LD @id (script context) (I1)

- **CWE:** CWE-79
- **Detail:** ?v=token reflects URL-encoded inside the <script> JSON-LD @id field; quote-breakout probe stripped - no raw quote breakout.

### 6. [INFO] Hidden /r and /go paths 301 to first-party content pages with param retained (I22)

- **CWE:** CWE-538
- **Detail:** /r?url 301 to /in-focus/remembering-september-11/?url=... and /go?url 301 to /programs/government/?url=... - external canary retained in the query string of first-party content pages; no open redirect.

### 7. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.harvard.edu/.

### 8. [LOW] No clickjacking protection (H4)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.harvard.edu/.

### 9. [LOW] Missing HSTS header (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.harvard.edu/.

### 10. [INFO] Missing Referrer-Policy (H5)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.harvard.edu/.

### 11. [INFO] test.harvard.edu 404 (Pantheon) (S1)

- **CWE:** CWE-916
- **Detail:** test.harvard.edu 404 (566 B Pantheon) - test subdomain hosted on the PaaS with no auth.

### 12. [LOW] login.harvard.edu Okta SSO with bookmark path (S1)

- **CWE:** CWE-916
- **Detail:** login.harvard.edu 302 to /home/bookmark/0oa1u9x1bsb6ZUklU1d8/2557 (Okta app id and bookmark exposed in the public redirect).

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
