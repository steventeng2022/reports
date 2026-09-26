# Security Audit Report — collegehumor.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://collegehumor.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | collegehumor.com |
| Test date | 2026-09-25 09:06 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 2, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL1 | Mail servers exist (MX) but no SPF record | CWE-200 |
| 3 | low | MAIL3 | No DMARC record | CWE-200 |
| 4 | low | RED1 | HTTP redirect points to another host over plain HTTP | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Mail servers exist (MX) but no SPF record (`MAIL1`)

- **CWE:** CWE-200
- **Detail:** MX records are published but no SPF TXT record; sender-domain spoofing is harder to validate.
- **Recommendation:** Publish an SPF record enumerating authorized senders.

### 3. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 4. [LOW] HTTP redirect points to another host over plain HTTP (`RED1`)

- **CWE:** CWE-319
- **Detail:** Location: http://dropout.tv/plans
- **Context:** https response, /
- **Recommendation:** Redirect to the same host over HTTPS.

## Evidence (raw response observations)

```json
{
  "domain": "collegehumor.com",
  "dns": {
    "a": [
      "3.33.139.32"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ha4.markmonitor.zone.",
      "ha3.markmonitor.zone.",
      "ha2.markmonitor.zone.",
      "ha1.markmonitor.zone."
    ],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "elapsed_s": 6.8,
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "rechecked": "2026-09-25 10:43 UTC",
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
    "status": 301,
    "location": "http://dropout.tv/plans"
  },
  "redir_probes": [],
  "paths": {}
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
