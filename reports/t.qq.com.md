# Security Audit Report — t.qq.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://t.qq.com/ |
| Bug bounty program | [Tencent](https://en.security.tencent.com) |
| Listed scope domain | qq.com |
| Test date | 2026-09-23 20:00 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 1, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | R3 | DNS does not resolve (endpoint unreachable) | CWE-1032 |

## Detailed findings

### 1. [LOW] DNS does not resolve (endpoint unreachable) (`R3`)

- **CWE:** CWE-1032
- **Detail:** Verified: both http://t.qq.com and https://t.qq.com fail DNS resolution (curl: Could not resolve host; getaddrinfo ENOENT). The Tencent Weibo hostname no longer resolves (service wound down); endpoint fully unreachable.
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

## Evidence (raw response observations)

```json
{
  "http_error": "getaddrinfo ENOENT t.qq.com",
  "https_error": "getaddrinfo ENOENT t.qq.com"
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
