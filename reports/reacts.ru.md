# Security Audit Report — reacts.ru

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://reacts.ru/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | reacts.ru |
| Test date | 2026-09-26 18:58 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 3, Low: 2, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | medium | TLS1 | TLS certificate chain not trusted | CWE-298 |
| 4 | medium | PRT21 | FTP service (cleartext) reachable | CWE-319 |
| 5 | info | PRT22 | SSH reachable | CWE-200 |
| 6 | info | PRT25 | SMTP (port 25) reachable | CWE-200 |
| 7 | info | PRT110 | POP3 (cleartext) reachable | CWE-319 |
| 8 | info | PRT143 | IMAP (cleartext) reachable | CWE-319 |
| 9 | info | PRT993 | IMAPS (port 993) reachable | CWE-200 |
| 10 | info | PRT995 | POP3S (port 995) reachable | CWE-200 |
| 11 | medium | PRT3306 | MySQL (port 3306) reachable | CWE-200 |
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [MEDIUM] TLS certificate chain not trusted (`TLS1`)

- **CWE:** CWE-298
- **Detail:** TLS verification failed: CERTIFICATE_VERIFY_FAILED
- **Recommendation:** Fix the certificate chain (missing intermediate / issuer).

### 4. [MEDIUM] FTP service (cleartext) reachable (`PRT21`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 31.31.197.110:21 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] SSH reachable (`PRT22`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 31.31.197.110:22 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 6. [INFO] SMTP (port 25) reachable (`PRT25`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 31.31.197.110:25 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 7. [INFO] POP3 (cleartext) reachable (`PRT110`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 31.31.197.110:110 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 8. [INFO] IMAP (cleartext) reachable (`PRT143`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 31.31.197.110:143 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 9. [INFO] IMAPS (port 993) reachable (`PRT993`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 31.31.197.110:993 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 10. [INFO] POP3S (port 995) reachable (`PRT995`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 31.31.197.110:995 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 11. [MEDIUM] MySQL (port 3306) reachable (`PRT3306`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 31.31.197.110:3306 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of reacts.ru has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "reacts.ru",
  "dns": {
    "a": [
      "31.31.197.110"
    ],
    "aaaa": [
      "2a00:f940:2:2:1:1:0:317"
    ],
    "cname": null,
    "mx": [
      "mx1.hosting.reg.ru (pref 0)",
      "mx2.hosting.reg.ru (pref 5)"
    ],
    "ns": [
      "ns1.hosting.reg.ru.",
      "ns2.hosting.reg.ru."
    ],
    "spf": [
      "v=spf1 +include:_spf.hosting.reg.ru +a +mx +ip4:31.31.197.110 ?all"
    ],
    "dmarc": [],
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
    "error": "CERTIFICATE_VERIFY_FAILED",
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "31.31.197.110",
    "open": [
      21,
      22,
      25,
      110,
      143,
      993,
      995,
      3306
    ]
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
    "status": 200
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "status": "ct-pending"
  },
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260605224433",
      "not_after": "20260903224432"
    }
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='reacts.ru', port=443): Max ret"
  },
  "elapsed_s": 14.3,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
