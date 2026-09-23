# Security Audit Report — periscope.tv

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://periscope.tv/ |
| Bug bounty program | [Twitter](https://hackerone.com/twitter) |
| Listed scope domain | periscope.tv |
| Test date | 2026-09-23 19:02 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 3, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H2 | Missing CSP header | CWE-1021 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |

## Detailed findings

### 1. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://periscope.tv/",
  "https_status": 302,
  "content_type": "text/plain; charset=utf-8",
  "title": "",
  "path_gitconfig": 302,
  "path_envfile": 302,
  "path_securitytxt": 302,
  "path_robots": 302
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
