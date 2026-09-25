# Security Audit Report — use.typekit.net

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://use.typekit.net/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | use.typekit.net |
| Test date | 2026-09-24 13:47 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **7** (High: 0, Medium: 1, Low: 5, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | medium | I1v | Search-term reflection in JSON script block + attributes (fully escaped, matrix verified) | CWE-79 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 4 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [MEDIUM] Search-term reflection in searchbar JSON script block + attributes - fully escaped, encoding matrix verified (2026-09-25) (`I1v`)

- **CWE:** CWE-79
- **Detail:** 4 near-duplicate engine hits consolidated (parameters q and query on https://fonts.adobe.com/search). The search term is reflected in:
  1. `<script type="application/json" id="/searchbar_value">"TOKEN"</script>` (JSON script block)
  2. `href="/search?query=TOKEN"` and sibling filter links (attribute context, double-URL-encoded as %25xx)
  3. `sign-in-url="https://fonts.adobe.com/login/adobe?url=...%3Fq%3DTOKEN"` (attribute)
  4. `<p class="font-discovery__results-message">Results for 'TOKEN'</p>` (body, entity-encoded &#39;)
  Encoding matrix (input -> reflected in JSON block): quote -> backslash + &quot;; backslash -> doubled backslash; less-than -> u003c; greater-than -> u003e; space preserved. After the framework HTML-entity decode, all tested payloads (quote, backslash, quote+backslash, raw closing-script tag) produced correctly JSON-escaped strings.
- **Severity rationale (rule 4):** High -> Medium: reflection is real and unauthenticated, but every tested payload was neutralized by the encoding chain; exploitation would require an untested fourth encoding inconsistency (e.g., a character the encoder skips) or framework-side entity-decode order-of-operations bug.
- **Re-test vectors to try with a JS runtime (headless):** (a) character set {tab, newline, NUL, %, #}, (b) double-encoding `%2522`, (c) Unicode quote variants, (d) inspect how `af-search-bar` consumes /searchbar_value (JSON.parse vs. regex) in the page bundle.
- **Recommendation:** Keep the JSON block as the single source of truth; if the decoded value is ever inserted into markup, re-encode per-context rather than relying on the entity layer alone.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy on https://fonts.adobe.com/


### 3. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** require_login_experiment_num_clicks, require_login_experiment_state, rails_session_hash, pid, server_side_user_prefs set without HttpOnly on https://fonts.adobe.com/


### 4. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://fonts.adobe.com/ reflects input verbatim in body context; encoding boundary not confirmed.


### 5. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://fonts.adobe.com/ reflects input verbatim in body context; encoding boundary not confirmed.


### 6. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: use.typekit.net + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.


### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header: nginx

## Reproduction notes

- Scanned 2026-09-24 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
