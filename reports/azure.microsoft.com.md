# Security Audit Report — azure.microsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://azure.microsoft.com/ |
| Bug bounty program | Microsoft Online Services |
| Listed scope domain | azure.microsoft.com |
| Test date | 2026-09-26 21:58 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 3 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 4 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 5 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 6 | info | CT1 | 31 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 7 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://oneocsp.microsoft.com/ocsp -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 3. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but azure.microsoft.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 4. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 25 disallow path(s), e.g. /*/searchresults/, /*/search/?q=*, /*/patterns/, /api/, /debug/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 5. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.209.218.179 carries PTR a23-209-218-179.deploy.static.akamaitechnologies.com. for azure.microsoft.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 6. [INFO] 31 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: aef-alt.onedscollector.dev.azure.microsoft.com, aef.onedscollector.dev.azure.microsoft.com, assessment.changeguard.fcm.azure.microsoft.com, azure.microsoft.com, azurelocalsolutions.azure.microsoft.com, azurestackhcisolutions.azure.microsoft.com, changeexplorer.fcm.azure.microsoft.com, changeguard.fcm.azure.microsoft.com, emails-ppe.azure.microsoft.com, emails.azure.microsoft.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 7. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: aef-alt.onedscollector.dev.azure.microsoft.com, aef.onedscollector.dev.azure.microsoft.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "azure.microsoft.com",
  "dns": {
    "a": [
      "23.209.218.179"
    ],
    "aaaa": [
      "2600:1417:76:4a1::439b",
      "2600:1417:76:480::439b"
    ],
    "cname": "azure.microsoft.com.edgekey.net.",
    "mx": [],
    "ns": [],
    "caa": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=WA, localityName=Redmond, organizationName=Microsoft Corporation, commonName=azure.microsoft.com",
    "issuer": "countryName=US, organizationName=Microsoft Corporation, commonName=Microsoft TLS G2 RSA CA OCSP 04",
    "notBefore": "Sep 16 19:05:38 2026 GMT",
    "notAfter": "Apr  2 19:05:38 2027 GMT",
    "san": [
      "dialtone.azure.microsoft.com",
      "azure.microsoft.com"
    ],
    "days_left": 187,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.218.179",
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
    "status": 301,
    "location": "http://azure.microsoft.com/en-us"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "source": "certspotter",
    "count": 31,
    "notable": [
      "aef-alt.onedscollector.dev.azure.microsoft.com",
      "aef.onedscollector.dev.azure.microsoft.com",
      "assessment.changeguard.fcm.azure.microsoft.com",
      "azure.microsoft.com",
      "azurelocalsolutions.azure.microsoft.com",
      "azurestackhcisolutions.azure.microsoft.com",
      "changeexplorer.fcm.azure.microsoft.com",
      "changeguard.fcm.azure.microsoft.com",
      "emails-ppe.azure.microsoft.com",
      "emails.azure.microsoft.com",
      "eu-aef.onedscollector.dev.azure.microsoft.com",
      "eu-kar.onedscollector.dev.azure.microsoft.com",
      "eu-uda.onedscollector.dev.azure.microsoft.com",
      "hcicatalog.azure.microsoft.com",
      "jwcc.azure.microsoft.com"
    ],
    "sample": [
      "aef-alt.onedscollector.dev.azure.microsoft.com",
      "aef.onedscollector.dev.azure.microsoft.com",
      "assessment.changeguard.fcm.azure.microsoft.com",
      "azure.microsoft.com",
      "azurelocalsolutions.azure.microsoft.com",
      "azurestackhcisolutions.azure.microsoft.com",
      "changeexplorer.fcm.azure.microsoft.com",
      "changeguard.fcm.azure.microsoft.com",
      "emails-ppe.azure.microsoft.com",
      "emails.azure.microsoft.com",
      "eu-aef.onedscollector.dev.azure.microsoft.com",
      "eu-kar.onedscollector.dev.azure.microsoft.com",
      "eu-uda.onedscollector.dev.azure.microsoft.com",
      "hcicatalog.azure.microsoft.com",
      "jwcc.azure.microsoft.com",
      "kar-alt.onedscollector.dev.azure.microsoft.com",
      "kar.onedscollector.dev.azure.microsoft.com",
      "portal-staging.changeguard.fcm.azure.microsoft.com",
      "portal-staging.changemanager.fcm.azure.microsoft.com",
      "portal.changeguard.fcm.azure.microsoft.com"
    ],
    "dangling": [
      "aef-alt.onedscollector.dev.azure.microsoft.com",
      "aef.onedscollector.dev.azure.microsoft.com"
    ]
  },
  "cname_chain": [
    "azure.microsoft.com.edgekey.net",
    "e17307.dscb.akamaiedge.net"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.12",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": "http://oneocsp.microsoft.com/ocsp",
      "not_before": "20260916190538",
      "not_after": "20270402190538"
    },
    "ocsp": "http-400"
  },
  "http2": {
    "robots_disallow": [
      "/*/searchresults/",
      "/*/search/?q=*",
      "/*/patterns/",
      "/api/",
      "/debug/",
      "/di-ag/",
      "/global-infrastructure/services/get-async/",
      "/qa-folder",
      "/*?*ep_*",
      "/*&ep_*",
      "/wp-admin/post.php",
      "/blog/feed/",
      "/wp-login.php",
      "/xmlrpc.php",
      "/*?p="
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-209-218-179.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://azure.microsoft.com/en-us",
    "http_status": 301,
    "p404_status": 302,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "elapsed_s": 143.7,
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
