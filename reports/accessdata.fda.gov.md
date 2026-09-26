# Security Audit Report — accessdata.fda.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://accessdata.fda.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | accessdata.fda.gov |
| Test date | 2026-09-26 01:45 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **4** (High: 0, Medium: 1, Low: 0, Info: 3)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS1 | TLS certificate chain not trusted | CWE-298 |
| 3 | info | TLS9 | Neither TLS 1.2 nor 1.3 handshake succeeded | CWE-327 |
| 4 | info | CT1 | 5 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] TLS certificate chain not trusted (`TLS1`)

- **CWE:** CWE-298
- **Detail:** TLS verification failed: [WinError 10054] 遠端主機已強制關閉一個現存的連線。
- **Recommendation:** Fix the certificate chain (missing intermediate / issuer).

### 3. [INFO] Neither TLS 1.2 nor 1.3 handshake succeeded (`TLS9`)

- **CWE:** CWE-327
- **Detail:** Only legacy protocols (if any) could complete a handshake.
- **Recommendation:** Upgrade TLS configuration.

### 4. [INFO] 5 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "accessdata.fda.gov",
  "dns": {
    "a": [
      "23.11.91.198"
    ],
    "aaaa": [
      "2600:1417:76:480::308a",
      "2600:1417:76:4a1::308a"
    ],
    "cname": "resolver.fda.gov.akadns.net.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; ri=3600; rua=mailto:rua.dmarc@fda.hhs.gov,mailto:reports@dmarc.cyber.dhs.gov,mailto:8idhoybh@ag.us.dmarcian.com; ruf=mailto:ruf.dmarc@fda.hhs.gov;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "untrusted",
    "version": null,
    "cipher": null,
    "subject": null,
    "issuer": null,
    "notBefore": null,
    "notAfter": null,
    "san": null,
    "error": "[WinError 10054] 遠端主機已強制關閉一個現存的連線。",
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": false,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "23.11.91.198",
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
    "status": 400
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "source": "certspotter",
    "count": 5,
    "notable": [],
    "sample": [
      "cacmap.accessdata.fda.gov",
      "origin-aws.www.accessdata.fda.gov",
      "origin-em.www.accessdata.fda.gov",
      "www.accessdata.fda.gov",
      "www.origin-aws.www.accessdata.fda.gov"
    ]
  },
  "elapsed_s": 3.6,
  "rechecked": "2026-09-26 01:45 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
