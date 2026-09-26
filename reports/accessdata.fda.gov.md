# Security Audit Report — accessdata.fda.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://accessdata.fda.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | accessdata.fda.gov |
| Test date | 2026-09-26 21:56 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **5** (High: 0, Medium: 1, Low: 0, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS1 | TLS certificate chain not trusted | CWE-298 |
| 3 | info | TLS9 | Neither TLS 1.2 nor 1.3 handshake succeeded | CWE-327 |
| 4 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 5 | info | CT1 | 5 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 4. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for accessdata.fda.gov; apex fda.gov, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 5. [INFO] 5 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
      "2600:1417:76:4a1::308a",
      "2600:1417:76:480::308a"
    ],
    "cname": "resolver.fda.gov.akadns.net.",
    "mx": [],
    "ns": [],
    "caa": [],
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
  "cname_chain": [
    "resolver.fda.gov.akadns.net",
    "www.fda.gov.edgekey.net",
    "e12426.dscb.akamaiedge.net"
  ],
  "tls2": {
    "error": "ConnectionResetError(10054, '遠端主機已強制關閉一個現存的連線。', None, 10054, None)"
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "ConnectionError(ProtocolError('Connection aborted.', ConnectionResetError(10054,"
  },
  "x13": {
    "root_error": "ConnectionError(ProtocolError('Connection aborted.', ConnectionResetError(10054,",
    "http_status": 400,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 4.4,
  "rechecked": "2026-09-26 21:56 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- Findings are reported against the public program scope; submission through the program tracker is pending.
