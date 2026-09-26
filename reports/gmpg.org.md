# Security Audit Report — gmpg.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gmpg.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gmpg.org |
| Test date | 2026-09-25 18:32 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **3** (High: 0, Medium: 0, Low: 1, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | info | CT1 | 3 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [INFO] 3 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: staging.gmpg.org, www.staging.gmpg.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "gmpg.org",
  "dns": {
    "a": [
      "66.155.40.24"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "gmpg.org (pref 0)"
    ],
    "ns": [
      "ns1.mobiusltd.com.",
      "ns2.mobiusltd.com."
    ],
    "spf": [
      "v=spf1 +a +mx +ip4:66.155.40.30 +ip4:66.155.40.24 ~all"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "elapsed_s": 7.7,
  "rechecked": "2026-09-25 18:50 UTC",
  "tls_error": "TimeoutError('timed out')",
  "ports": {
    "ip": "66.155.40.24",
    "open": []
  },
  "https": {
    "status": 0,
    "content_type": "",
    "title": "",
    "error": "https connect failed"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [],
  "http": {
    "status": 0,
    "error": "http connect failed"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "source": "certspotter",
    "count": 3,
    "notable": [
      "staging.gmpg.org",
      "www.staging.gmpg.org"
    ],
    "sample": [
      "gmpg.org",
      "staging.gmpg.org",
      "www.staging.gmpg.org"
    ]
  }
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
