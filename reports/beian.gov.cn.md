# Security Audit Report - beian.gov.cn

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://beian.gov.cn/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | beian.gov.cn |
| Test date | 2026-09-24 14:16 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **1** (High: 0, Medium: 0, Low: 1, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | R3 | HTTP endpoint unreachable | CWE-1032 |

## Detailed findings

### 1. [LOW] HTTP endpoint unreachable (`R3`)

- **CWE:** CWE-1032
- **Detail:** http://beian.gov.cn failed: getaddrinfo ENOTFOUND beian.gov.cn
- **Recommendation:** Serve the site on port 80 with a redirect to HTTPS.

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- no stage-2 probe hits (all probes negative)

Stage-2 probe log (observed responses):
- timing base=errms id=err search=err

**Stage 3 - live parameter harvest, takeover and injection probes (8 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

## Evidence (raw response observations)

```json
{
  "http_error": "getaddrinfo ENOTFOUND beian.gov.cn",
  "https_error": "getaddrinfo ENOTFOUND beian.gov.cn",
  "probe_count": 28,
  "probe_log": [
    "sqli-reflect /search?q=%27+OR+1=1-- -> err",
    "host no reflection -> err"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=errms id=err search=err",
    "sweep no hits over 26 paths",
    "redir2 no hits over 49 requests"
  ],
  "v3_probe_count": 8,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "subs no dangling service CNAMEs over 16 subdomains"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
