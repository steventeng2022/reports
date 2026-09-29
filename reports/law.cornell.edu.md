# Security Audit Report — law.cornell.edu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://law.cornell.edu/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | law.cornell.edu |
| Test date | 2026-09-29 19:33 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 12, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I24 | Double-encoded reflected XSS (HTML-entity input decoded without re-encoding) | CWE-79 |
| 2 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 4 | low | T3 | HTTP redirect does not go to HTTPS | CWE-319 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 13 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 14 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 15 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Double-encoded reflected XSS (HTML-entity input decoded without re-encoding) (`I24`)

- **CWE:** CWE-79
- **Detail:** Parameter include on https://www.law.cornell.edu/sites/default/files/css/css_CwLET6eFl1hPUA5jvbCMXzyXgFBtfYYBJCo4rBFzFe8.css: sending &#x3C;svg id="zxe2e7"&#x3E; yields a raw <svg id="zxe2e7"> tag in the response; entity decoding without re-escaping lets payloads bypass naive encoders.

### 2. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.law.cornell.edu/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.law.cornell.edu/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] HTTP redirect does not go to HTTPS (`T3`)

- **CWE:** CWE-319
- **Detail:** GET http://law.cornell.edu/ redirected to http://www.law.cornell.edu/ (not an HTTPS URL).

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security on https://www.law.cornell.edu/

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://www.law.cornell.edu/

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors on https://www.law.cornell.edu/

### 8. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /includes/ which returns 403, indicating a hidden/protected resource exists at that path.

### 9. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter language on https://www.law.cornell.edu/sites/default/files/css/css_CwLET6eFl1hPUA5jvbCMXzyXgFBtfYYBJCo4rBFzFe8.css reflects input verbatim in body context; encoding boundary not confirmed.

### 10. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter theme on https://www.law.cornell.edu/sites/default/files/css/css_CwLET6eFl1hPUA5jvbCMXzyXgFBtfYYBJCo4rBFzFe8.css reflects input verbatim in body context; encoding boundary not confirmed.

### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter include on https://www.law.cornell.edu/sites/default/files/css/css_CwLET6eFl1hPUA5jvbCMXzyXgFBtfYYBJCo4rBFzFe8.css reflects input verbatim in body context; encoding boundary not confirmed.

### 12. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: law.cornell.edu + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 13. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.law.cornell.edu/

### 14. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.law.cornell.edu/

### 15. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **I1 #2/#3 (HIGH -> LOW):** fresh token Bd5Xn8JqWz on /?q= reflects exactly once, inside <script type="application/json" data-drupal-selector="drupal-settings-json"> as "currentQuery":{"q":"..."} - a JSON data block, not executable JS. Breakout payloads: ?q=%3C%2Fscript%3E%3Csvg%20onload%3Dalert(1)%3E renders as </script><svg... (Drupal drupal_json_encode hex-escapes < > & and slashes) and ?q=%22%3Balert(1)// renders with the quote JSON-escaped - no raw </script> or raw quote anywhere in the document. Same FP family as the 14+30 refuted I1/I30 clusters (w3.org R13, vizio, activecampaign).
- **I24 #1 (HIGH -> LOW):** the css_CwLET6eFl1hPUA5jvbCMXzyXgFBtfYYBJCo4rBFzFe8.css aggregation URL now returns 400 44B "The theme must be passed as a query argument" (Drupal CSS aggregation changed to require ?theme=), so the ?include= reflection vector is gone (no reflection with or without parameter). Additionally /?include=%3Csvg id=zxe2e7%3E reflects only in drupal-settings-json as <svg id="zxe2e7"> (fully hex-escaped, raw <svg> absent).
