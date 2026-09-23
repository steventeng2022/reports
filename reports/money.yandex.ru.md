# Security Audit Report — money.yandex.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://money.yandex.ru/ |
| Bug bounty program | [Yandex](https://yandex.com/bugbounty/index) |
| Listed scope domain | yandex.ru |
| Test date | 2026-09-23 20:59 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 1, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | R3 | HTTP endpoint unreachable | CWE-1032 |

## Detailed findings

### 1. [LOW] HTTP endpoint unreachable (`R3`)

- **CWE:** CWE-1032
- **Detail:** http://money.yandex.ru failed: getaddrinfo ENOTFOUND money.yandex.ru
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

## Evidence (raw response observations)

```json
{
  "http_error": "getaddrinfo ENOTFOUND money.yandex.ru",
  "https_error": "getaddrinfo ENOTFOUND money.yandex.ru"
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
