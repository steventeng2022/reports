# Security Audit Report — www.ietf.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://www.ietf.org/admin/login/?next=/admin/ |
| Bug bounty program | IETF |
| Listed scope domain | ietf.org |
| Test date | 2026-09-26 04:41 UTC |
| Method | Active testing against the Wagtail admin login: redirect-validation matrix on the `next` parameter, login-form reflection and enumeration, password-reset flow, HTTP methods, host-header behavior, static-asset fingerprinting (hash match against PyPI release wheels), response header and cookie review; non-destructive, no valid credentials, site behind Cloudflare |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 3, Info: 8)

The target is a **Wagtail 7.4.3** CMS admin (login page titled "Sign in - Wagtail"; static JS bundle hash-matched against the Wagtail 7.4.3 PyPI wheel), which requires Django >= 5.2, served behind Cloudflare. The open-redirect surface on `next` is strongly defended by Django's `url_has_allowed_host_and_scheme`; remaining findings are hygiene items (missing HSTS/CSP, cookie attributes, control characters preserved in the validated redirect target, version fingerprinting).

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | C1 | csrftoken cookie missing Secure attribute | CWE-614 |
| 4 | info | V1 | Wagtail 7.4.3 / Django >= 5.2 version fingerprint via static asset hash | CWE-200 |
| 5 | info | R1 | Login next parameter accepts same-host absolute URL (case-insensitive scheme) | CWE-601 |
| 6 | info | R2 | Backslash-leading next value (\evil.example/) passes validation as relative | CWE-601 |
| 7 | info | R3 | Control characters (NUL, tab, space, LF) preserved in validated next value | CWE-601 |
| 8 | info | I1 | Username re-echoed on failed login (escaped; response length tracks input length) | CWE-200 |
| 9 | info | I2 | Client maxlength=150 vs server max_length=254 mismatch on username | CWE-20 |
| 10 | info | H3 | Missing Permissions-Policy header | CWE-200 |
| 11 | info | S1 | No .well-known/security.txt (404) | CWE-200 |

## Detailed findings

### 1. [LOW] Missing HSTS header (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.ietf.org/admin/login/ (fresh capture 2026-09-26 04:41 UTC). Consistent with the ietf.org root finding; the admin surface has no HSTS pin.

### 2. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on the admin login page. The page loads many admin JS bundles; a CSP would bound the impact of any future script injection.

### 3. [LOW] csrftoken cookie missing Secure attribute (C1)

- **CWE:** CWE-614
- **Detail:** The login page sets: Set-Cookie: csrftoken=...; expires=...; Max-Age=31449600; Path=/; SameSite=Lax — no Secure flag. With no HSTS and no HTTP->HTTPS enforcement, the cookie could in principle be carried over an unencrypted connection. SameSite=Lax limits cross-site use. (Not HttpOnly, which is standard for CSRF tokens.)

### 4. [INFO] Wagtail 7.4.3 / Django >= 5.2 version fingerprint via static asset hash (V1)

- **CWE:** CWE-200
- **Detail:** GET /static/wagtailadmin/js/core.83202c8036ac.js is byte-identical (SHA-256 142B19155DAB97845D6F9C5793D3C6B998BED71A86347A3DAB744D71D937F49F) to wagtail/admin/static/wagtailadmin/js/core.js inside the Wagtail 7.4.3 wheel on PyPI; wheels from 5.2.8 through 7.4.3 were compared and only 7.4.3 matched. Corroboration: page title "Sign in - Wagtail" and the embedded wagtail-config JSON (admin API URLs, CSRF header name X-Csrftoken, second masked CSRF token). Wagtail 7.4.x requires Django >= 5.2, so the framework pair is pinned for CVE triage.

### 5. [INFO] Login next parameter accepts same-host absolute URL (R1)

- **CWE:** CWE-601
- **Detail:** GET /admin/login/?next=https://www.ietf.org/ (and HTTPS://www.ietf.org/ — scheme comparison is case-insensitive) is accepted and reflected into the hidden next field used for the post-login redirect. Django's url_has_allowed_host_and_scheme permits absolute URLs on the same host when require_https is met. Same-host, so not an open redirect, but post-login navigation can be steered to any absolute path on the site.

### 6. [INFO] Backslash-leading next value passes validation as relative (R2)

- **CWE:** CWE-601
- **Detail:** ?next=\evil.example/ is accepted: a leading backslash is not normalized the way // is, so the value parses as a relative path and survives validation with the backslash intact. Contrasts with /\evil.example/ and //evil.example/, which are rejected and fall back to /admin/. Browsers normalize \ to / during navigation, so this is an edge-case hygiene item rather than an open redirect.

### 7. [INFO] Control characters preserved in validated next value (R3)

- **CWE:** CWE-601
- **Detail:** Validated next values retain embedded control characters that land in the post-login Location header: /admin/%00 (NUL preserved), %09/admin/ (leading tab), %20/admin/ (leading space), and https://www.ietf.org/%0a (raw LF, U+000A, preserved after percent-decoding). Single LF is not a CRLF injection, but raw control characters in Location are sloppy header hygiene.

### 8. [INFO] Username re-echoed on failed login (I1)

- **CWE:** CWE-200
- **Detail:** On failed login the submitted username is re-echoed into value="..." in the login form (HTML-escaped). Same-length existing (admin) vs nonexistent (adman) usernames return identical response sizes (13580 bytes) with comparable timing (~550-620 ms); response size varies only with input length, so only length is leaked, not existence. Error text is generic: "Your username and password didn't match. Please try again."

### 9. [INFO] Client maxlength=150 vs server max_length=254 mismatch (I2)

- **CWE:** CWE-20
- **Detail:** The login username input declares maxlength="150" while the server form validates up to 254 characters (255 chars -> form error "Ensure this value has at most 254 characters (it has 255)."; 200 chars passes validation and reaches the auth check). The 151-254 range is reachable programmatically.

### 10. [INFO] Missing Permissions-Policy header (H3)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on the admin login page.

### 11. [INFO] No .well-known/security.txt (S1)

- **CWE:** CWE-200
- **Detail:** https://www.ietf.org/.well-known/security.txt returns 404 (site 404 page), so there is no published disclosure policy.

## Controls verified (no findings)

- **Open-redirect defense on next is strong:** https://evil.example/, //evil.example/, ///evil.example/, https://www.ietf.org.evil.example/, https://www.ietf.org@evil.example/, https://www.ietf.org:8443/, https://ietf.org/ and http://www.ietf.org/ (require_https) are all rejected with fallback to /admin/; javascript:alert(1) in the query is blocked by the Cloudflare WAF (403).
- **Host-header attacks:** Host: ietf.org -> 301 to the canonical host (query dropped); admin.ietf.org / evil.ietf.org -> 530 (Cloudflare); localhost / 127.0.0.1 / evil.com -> 403 (Cloudflare); www.ietf.org:443 -> 200 but next re-validated. No open redirect via Host.
- **Password reset:** /admin/password_reset/ enabled; nonexistent and existing addresses both return the same 302 to /admin/password_reset/done/ with comparable timing (~0.27-0.7 s); completion page wording is generic ("A link to reset your password has been emailed to you if an account exists for this address."). No user enumeration observed.
- **Unauthenticated admin surface:** /admin/, /admin/pages/, /admin/users/, /admin/account/, /admin/api/main/*, /admin/dismissibles/, and unknown /admin/* paths all 302 to login with a server-generated next; no sessionid is set pre-login; all source maps 404; /admin/sprite/ is a public 64 KB SVG icon sprite (harmless).
- **Methods:** OPTIONS 200; PUT/PATCH/DELETE 403 (CSRF).
- **CSRF:** Django 4.1+ masked tokens (three differing masked values for one raw secret is expected); on HTTPS the Origin header is checked first — POSTs without Origin get 403 even with a valid token.
- **Headers present:** X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Cross-Origin-Opener-Policy: same-origin, Referrer-Policy: same-origin, Cache-Control: no-cache/no-store.
- **Cloudflare WAF:** backtick/quote payloads in the POST body are blocked ("Sorry, you have been blocked", 5483 B page), providing defense-in-depth for the reflected username.

## Reproduction notes

- Tested 2026-09-26 from Asia/Taipei (UTC+8) via HTTPS through Cloudflare; non-destructive. Several failed logins (200/255-char usernames, XSS payloads) and ~6 password-reset POSTs were made, of which 4 used admin@ietf.org — a few reset emails may have been sent to that address.
- Working POST recipe: fresh GET of the login page to obtain a new csrftoken + csrfmiddlewaretoken, then POST in the same session with Content-Type: application/x-www-form-urlencoded and Origin: https://www.ietf.org (Django 5.2 checks Origin first on HTTPS; without it the request is 403 "Referer header required" even with a valid token).
- next matrix examples: curl -sS "https://www.ietf.org/admin/login/?next=https://www.ietf.org/" (accepted), ?next=\evil.example/ (accepted), ?next=//evil.example/ (rejected -> /admin/), ?next=https://www.ietf.org/%0a (raw LF preserved in the reflected value).
- curl -L -X POST note: following the password-reset 302 with -X POST keeps the POST method but drops the body (no Content-Length), so the CSRF token is missing and the done page returns 403 "CSRF verification failed. Request aborted." A manual POST to /admin/password_reset/done/ with token + Origin returns 405 (correct). This is client behavior, not a server finding.
