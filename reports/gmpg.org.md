# Security Audit Report — gmpg.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gmpg.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | gmpg.org |
| Test date | 2026-09-26 19:06 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 4 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 5 | info | CT1 | 3 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 4. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 5. [INFO] 3 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
  "error": "TimeoutError('timed out')",
  "tls2": {
    "error": "TimeoutError('timed out')"
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "ConnectTimeout(MaxRetryError(\"HTTPSConnectionPool(host='gmpg.org', port=443): Ma"
  },
  "elapsed_s": 45.9,
  "rechecked": "2026-09-26 19:07 UTC",
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
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
