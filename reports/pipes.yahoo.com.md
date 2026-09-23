# Security Audit Report — pipes.yahoo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pipes.yahoo.com/ |
| Bug bounty program | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| Listed scope domain | yahoo.com |
| Test date | 2026-09-23 19:25 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 1, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | R3 | DNS does not resolve (endpoint unreachable) | CWE-1032 |

## Detailed findings

### 1. [LOW] DNS does not resolve (endpoint unreachable) (`R3`)

- **CWE:** CWE-1032
- **Detail:** Verified: both http://pipes.yahoo.com and https://pipes.yahoo.com fail with getaddrinfo ENOTFOUND (curl: Could not resolve host). The Yahoo Pipes hostname no longer resolves in DNS (service deprecated); endpoint fully unreachable.
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

## Evidence (raw response observations)

```json
{
  "http_error": "getaddrinfo ENOTFOUND pipes.yahoo.com",
  "https_error": "getaddrinfo ENOTFOUND pipes.yahoo.com"
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
