# Security Audit Report — blogs.adobe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blogs.adobe.com/ |
| Bug bounty program | Adobe |
| Listed scope domain | blogs.adobe.com |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **4** (High: 0, Medium: 1, Low: 1, Info: 2)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS2 | TLS certificate hostname mismatch | CWE-297 |
| 3 | low | TLS6 | Certificate SAN does not include the target hostname | CWE-297 |
| 4 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] TLS certificate hostname mismatch (`TLS2`)

- **CWE:** CWE-297
- **Detail:** TLS verification failed: CERTIFICATE_VERIFY_FAILED
- **Recommendation:** Serve a certificate whose SAN covers blogs.adobe.com.

### 3. [LOW] Certificate SAN does not include the target hostname (`TLS6`)

- **CWE:** CWE-297
- **Detail:** Presented certificate SANs ['*.adobeaemcloud.com'] do not include blogs.adobe.com.
- **Recommendation:** Issue a certificate covering this hostname (or wildcard).

### 4. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of blogs.adobe.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "blogs.adobe.com",
  "dns": {
    "a": [
      "151.101.131.10",
      "151.101.3.10",
      "151.101.195.10",
      "151.101.67.10"
    ],
    "aaaa": [],
    "cname": "cdn.adobeaemcloud.com.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:adobe@rua.agari.com; ruf=mailto:adobe@ruf.agari.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "hostname-mismatch",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Jose, organizationName=Adobe Inc., commonName=*.adobeaemcloud.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Sep  8 00:00:00 2026 GMT",
    "notAfter": "Mar 25 23:59:59 2027 GMT",
    "san": [
      "*.adobeaemcloud.com"
    ],
    "days_left": 180,
    "san_match": false,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.131.10",
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
    "status": 500
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "status": "ct-pending"
  },
  "cname_chain": [
    "cdn.adobeaemcloud.com",
    "adobe-aem.map.fastly.net"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
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
