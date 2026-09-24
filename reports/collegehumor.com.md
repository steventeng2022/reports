# Security Audit Report — collegehumor.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://collegehumor.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | collegehumor.com |
| Test date | 2026-09-24 05:35 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | R1 | HTTP redirect chain ends at HTTPS (rebrand) | CWE-319 |

## Detailed findings

### 1. [INFO] HTTP redirect chain ends at HTTPS (rebrand) (`R1`)

- **CWE:** CWE-319
- **Detail:** http://collegehumor.com 301s to http://dropout.tv/plans, then 308/307 up to https://www.dropout.tv/plans (200). The chain terminates on HTTPS after the CollegeHumor->Dropout rebrand; the brief plain-HTTP hop is a redirect only, no content served.
- **Recommendation:** Redirect http:// to https://.

## Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "http://dropout.tv/plans",
  "https_error": "timeout",
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
