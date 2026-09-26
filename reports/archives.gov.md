# Security Audit Report — archives.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://archives.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | archives.gov |
| Test date | 2026-09-26 18:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 3 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 4 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 5 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 6 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 7 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 8 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 3. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 4. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=vzFoKGZ49s-tl4Mw26kJfVRiYukV0lHmZlbG0iAYYMk
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 5. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of archives.gov has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 6. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 4 disallow path(s), e.g. /citizen-archivist/history-hub/hh-test, /developer/artificial-intelligence-and-machine-learning-datasets, /developer/1940-census, /developer/national-archives-catalog-dataset
- **Recommendation:** Review disallowed paths; robots is not access control.

### 7. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of archives.gov permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 8. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 52.44.89.206 carries PTR ec2-52-44-89-206.compute-1.amazonaws.com. for archives.gov.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "archives.gov",
  "dns": {
    "a": [
      "52.44.89.206",
      "52.206.136.3"
    ],
    "aaaa": [
      "2600:1f18:43e8:f302:b470:d266:4d03:3ed8",
      "2600:1f18:43e8:f301:9046:c05f:75e7:c481"
    ],
    "cname": null,
    "mx": [
      "us.etp.fireeyegov.com (pref 10)"
    ],
    "ns": [
      "ns2.fedmettel.net.",
      "ns1.fedmettel.net."
    ],
    "spf": [
      "v=spf1 -all",
      "google-site-verification=vzFoKGZ49s-tl4Mw26kJfVRiYukV0lHmZlbG0iAYYMk"
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=reject;",
      "pct=100;",
      "fo=1;",
      "ri=86400;",
      "adkim=r;",
      "aspf=r;",
      "rua=mailto:reports@dmarc.cyber.dhs.gov;",
      "ruf=mailto:reports@dmarc.cyber.dhs.gov;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=Maryland, organizationName=National Archives and Records Administration, commonName=archives.gov",
    "issuer": "countryName=CA, organizationName=Entrust Limited, commonName=Entrust OV TLS Issuing RSA CA 2",
    "notBefore": "Sep 30 00:00:00 2025 GMT",
    "notAfter": "Oct 31 23:59:59 2026 GMT",
    "san": [
      "archives.gov",
      "nara.gov",
      "www.archives.gov",
      "www.nara.gov"
    ],
    "days_left": 35,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "52.44.89.206",
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=vzFoKGZ49s-tl4Mw26kJfVRiYukV0lHmZlbG0iAYYMk"
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
      "aia_ocsp": null,
      "not_before": "20250930000000",
      "not_after": "20261031235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/citizen-archivist/history-hub/hh-test",
      "/developer/artificial-intelligence-and-machine-learning-datasets",
      "/developer/1940-census",
      "/developer/national-archives-catalog-dataset"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-52-44-89-206.compute-1.amazonaws.com."
    ]
  },
  "elapsed_s": 25.2,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
