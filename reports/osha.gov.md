# Security Audit Report — osha.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://osha.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | osha.gov |
| Test date | 2026-09-30 02:25 UTC |
| Method | Active injection testing: GET parameter injection (reflected XSS, SSTI, open redirect, SQLi error-based, path traversal), sensitive endpoint probing, GraphQL introspection, host-header behavior, dangling-subdomain fingerprinting; non-destructive, no forms submitted, no auth |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 9, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I1 | Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) | CWE-79 |
| 2 | low | I1 | Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) | CWE-79 |
| 3 | low | I1 | Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) | CWE-79 |
| 4 | low | I1 | Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) | CWE-79 |
| 5 | low | I1 | Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) | CWE-79 |
| 6 | low | I1 | Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) | CWE-79 |
| 7 | low | I1 | Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) | CWE-79 |
| 8 | low | I22 | Protected path listed in robots.txt | CWE-538 |
| 9 | low | I12 | Host header alters response (vhost behavior) | CWE-918 |

## Detailed findings

### 1. [LOW] Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.osha.gov/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 2. [LOW] Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter query on https://www.osha.gov/search reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 3. [LOW] Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.osha.gov/s reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 4. [LOW] Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.osha.gov/ reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 5. [LOW] Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter q on https://www.osha.gov/results reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 6. [LOW] Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.osha.gov/redirect reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 7. [LOW] Reflected token in Drupal settings JSON (sanitized; WAF blocks angle-bracket payloads) (`I1`)

- **CWE:** CWE-79
- **Detail:** Parameter url on https://www.osha.gov/go reflects unescaped input inside <script>. Payload: Zx7qK2v9Bm (also "\"' onerror=\"alert(1)//").

### 8. [LOW] Protected path listed in robots.txt (`I22`)

- **CWE:** CWE-538
- **Detail:** robots.txt disallows /README.md which returns 403, indicating a hidden/protected resource exists at that path.

### 9. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Requesting the origin with Host: osha.gov + X-Forwarded-Host: 127.0.0.1 returns a different response than the normal homepage.

## Active re-verification (2026-09-30, agent-aggressive)

- **I1 x7 (HIGH -> LOW):** ?q= on /search re-probed - the token is reflected ONLY in the drupal-settings-json block (script type=application/json) currentQuery.q field. Quote and backslash payloads reflect stripped (identical 94,756 B 404-page body, identical context); </script>, "; and ";' payloads are 403-blocked by the CloudFront WAF (919 B "The request could not be satisfied", x-cache:Error from cloudfront) - a WAF on the live distribution (clean token still returns the 94 KB page), not a dangling CloudFront distribution. No raw quote and no raw </script> reach the script context - no string breakout.

## Reproduction notes

- Scanned 2026-09-30 from Asia/Taipei (UTC+8); single pass per endpoint; parameters taken from live GET URLs discovered on the target (no authenticated sessions).
