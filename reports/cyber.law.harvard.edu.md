# Security Audit Report — cyber.law.harvard.edu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cyber.law.harvard.edu/ |
| Bug bounty program | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| Listed scope domain | harvard.edu |
| Test date | 2026-09-24 00:53 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 1, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | R3 | HTTP endpoint unreachable | CWE-1032 |

## Detailed findings

### 1. [LOW] HTTP endpoint unreachable (`R3`)

- **CWE:** CWE-1032
- **Detail:** http://cyber.law.harvard.edu failed: connect ECONNREFUSED 128.103.64.74:80
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

## Evidence (raw response observations)

```json
{
  "http_error": "connect ECONNREFUSED 128.103.64.74:80",
  "https_error": "connect ECONNREFUSED 128.103.64.74:443"
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
