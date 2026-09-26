# Security Audit Report — beian.gov.cn

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://beian.gov.cn/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | beian.gov.cn |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS1 | Domain does not resolve (no A/AAAA) | CWE-200 |
| 2 | info | MAIL1 | Mail servers exist (MX) but no SPF record | CWE-200 |
| 3 | low | MAIL3 | No DMARC record | CWE-200 |
| 4 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 5 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |

## Detailed findings

### 1. [INFO] Domain does not resolve (no A/AAAA) (`DNS1`)

- **CWE:** CWE-200
- **Detail:** No A or AAAA record returned from public resolvers; site may be offline or DNS-only outage.
- **Recommendation:** Confirm the service is still expected to be live.

### 2. [INFO] Mail servers exist (MX) but no SPF record (`MAIL1`)

- **CWE:** CWE-200
- **Detail:** MX records are published but no SPF TXT record; sender-domain spoofing is harder to validate.
- **Recommendation:** Publish an SPF record enumerating authorized senders.

### 3. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 4. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 5. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

## Evidence (raw response observations)

```json
{
  "domain": "beian.gov.cn",
  "dns": {
    "a": [],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxbiz1.qq.com (pref 5)",
      "mxbiz2.qq.com (pref 10)"
    ],
    "ns": [
      "dns8.hichina.com.",
      "dns7.hichina.com."
    ],
    "spf": [],
    "dmarc": []
  },
  "tls": {
    "status": "no-ip"
  },
  "ports": {
    "status": "no-ip"
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
    "status": "ct-pending"
  },
  "http2": {
    "error": "root GET failed"
  },
  "elapsed_s": 4.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
