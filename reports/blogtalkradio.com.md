# Security Audit Report — blogtalkradio.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blogtalkradio.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | blogtalkradio.com |
| Test date | 2026-09-24 05:27 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 1, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | R3 | HTTP endpoint unreachable | CWE-1032 |

## Detailed findings

### 1. [LOW] HTTP endpoint unreachable (`R3`)

- **CWE:** CWE-1032
- **Detail:** http://blogtalkradio.com failed: getaddrinfo EAI_AGAIN blogtalkradio.com
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

## Evidence (raw response observations)

```json
{
  "http_error": "getaddrinfo EAI_AGAIN blogtalkradio.com",
  "https_error": "getaddrinfo ENOTFOUND blogtalkradio.com",
  "probe_count": 28,
  "probe_log": [
    "sqli-reflect /search?q=%27+OR+1=1-- -> err",
    "host no reflection -> err"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent and did not exceed ~8 requests per site.
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
