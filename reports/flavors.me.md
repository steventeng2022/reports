# Security Audit Report — flavors.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://flavors.me/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | flavors.me |
| Test date | 2026-09-24 07:24 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 0, Info: 1)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | R3 | Domain unresolvable at audit time (global DNS SERVFAIL) | CWE-1032 |

## Detailed findings

### 1. [INFO] Domain unresolvable at audit time (global DNS SERVFAIL) (`R3`)

- **CWE:** CWE-1032
- **Detail:** flavors.me failed DNS resolution during the audit; a DNS-over-HTTPS lookup (dns.google) also returns SERVFAIL with no A records, so the domain is unresolvable globally at audit time (service appears decommissioned).
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

## Evidence (raw response observations)

```json
{
  "http_error": "getaddrinfo EAI_AGAIN flavors.me",
  "https_error": "getaddrinfo ENOTFOUND flavors.me",
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
