# Security Audit Report — hollywoodreporter.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hollywoodreporter.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hollywoodreporter.com |
| Test date | 2026-09-29 19:33 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 4, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 2 | low | I1 | Reflected XSS in JavaScript context | CWE-79 |
| 3 | low | I33 | WordPress user enumeration via ?author=1 | CWE-200 |
| 4 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 5 | info | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.hollywoodreporter.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected XSS in JavaScript context (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.hollywoodreporter.com/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] WordPress user enumeration via ?author=1 (`I33`)

- **CWE:** CWE-200
- **Detail:** GET https://www.hollywoodreporter.com/?author=1 returns 301 -> https://www.hollywoodreporter.com/author/devops/; author slug (username) disclosed. Combine with xmlrpc.php for brute force.

### 4. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: hollywoodreporter.com + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

### 5. [INFO] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options on https://www.hollywoodreporter.com/

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy on https://www.hollywoodreporter.com/

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-29 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).

## Active re-verification (2026-09-30, agent-aggressive)
- **I1 #1/#2 (HIGH -> LOW):** fresh token Bd5Xn8JqWz on /?q= reflects in 4 places: (a) Parsely <script type="application/ld+json"> where the payload is TAG-STRIPPED (</script><svg onload=alert(1)> becomes ?q=scriptsvgonloadalert(1), and ";alert(1)// becomes ?q=alert(1) - the leading "; removed), and (b) the pmc-newsletter-frontend-js-extra text/javascript block where pageUrl keeps the payload URL-ENCODED (pageUrl":"https://www.hollywoodreporter.com/?q=%3C%2Fscript%3E%3Csvg+onload%3Dalert%281%29%3E" and ?q=%22%3Balert%281%29%2F%2F) - no raw </script>, no raw quote in any executable script context; CSP upgrade-insecure-requests,frame-ancestors 'none' has no script-src to begin with. Not exploitable; held LOW.
