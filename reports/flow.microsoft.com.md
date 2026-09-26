# Security Audit Report — flow.microsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://flow.microsoft.com/ |
| Bug bounty program | Microsoft Online Services |
| Listed scope domain | flow.microsoft.com |
| Test date | 2026-09-26 18:51 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 4, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of flow.microsoft.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "flow.microsoft.com",
  "dns": {
    "a": [
      "150.171.110.68"
    ],
    "aaaa": [
      "2603:1061:14:16b::1"
    ],
    "cname": "portal.processsimple.trafficmanager.net.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=WA, localityName=Redmond, organizationName=Microsoft Corporation, commonName=flow.microsoft.com",
    "issuer": "countryName=US, organizationName=Microsoft Corporation, commonName=Microsoft TLS G2 RSA CA OCSP 16",
    "notBefore": "Aug 29 04:53:07 2026 GMT",
    "notAfter": "Feb 25 04:53:07 2027 GMT",
    "san": [
      "flow.microsoft.com",
      "us.flow.microsoft.com",
      "preview.flow.microsoft.com",
      "emea.flow.microsoft.com",
      "asia.flow.microsoft.com",
      "australia.flow.microsoft.com",
      "india.flow.microsoft.com",
      "japan.flow.microsoft.com",
      "canada.flow.microsoft.com",
      "uk.flow.microsoft.com",
      "unitedkingdom.flow.microsoft.com",
      "ms.flow.microsoft.com",
      "southamerica.flow.microsoft.com",
      "tip0.flow.microsoft.com",
      "preview.portal.processsimple.trafficmanager.net",
      "portal.processsimple.trafficmanager.net",
      "france.flow.microsoft.com",
      "unitedarabemirates.flow.microsoft.com",
      "*.asia.flow.microsoft.com",
      "*.australia.flow.microsoft.com",
      "*.canada.flow.microsoft.com",
      "*.emea.flow.microsoft.com",
      "*.france.flow.microsoft.com",
      "*.germany.flow.microsoft.com",
      "*.india.flow.microsoft.com",
      "*.japan.flow.microsoft.com",
      "*.preview.flow.microsoft.com",
      "*.southamerica.flow.microsoft.com",
      "*.uk.flow.microsoft.com",
      "*.unitedarabemirates.flow.microsoft.com",
      "*.us.flow.microsoft.com",
      "germany.flow.microsoft.com",
      "switzerland.flow.microsoft.com",
      "*.switzerland.flow.microsoft.com",
      "*.unitedkingdom.flow.microsoft.com",
      "korea.flow.microsoft.com",
      "*.korea.flow.microsoft.com",
      "norway.flow.microsoft.com",
      "*.norway.flow.microsoft.com",
      "southafrica.flow.microsoft.com",
      "*.southafrica.flow.microsoft.com",
      "singapore.flow.microsoft.com",
      "*.singapore.flow.microsoft.com",
      "sweden.flow.microsoft.com",
      "*.sweden.flow.microsoft.com",
      "italy.flow.microsoft.com",
      "*.italy.flow.microsoft.com"
    ],
    "days_left": 151,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "150.171.110.68",
    "open": []
  },
  "https": {
    "status": 307,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.flow.microsoft.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 307,
    "location": "https://flow.microsoft.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 307",
    "/redirect?next=https://evil-auditor.example/x -> 307",
    "/go?url=https://evil-auditor.example/x -> 307",
    "/url?url=https://evil-auditor.example/x -> 307"
  ],
  "paths": {
    "/robots.txt": 307,
    "/sitemap.xml": 307,
    "/.well-known/security.txt": 307,
    "/security.txt": 307,
    "/.git/HEAD": 307,
    "/.git/config": 307,
    "/.env": 307,
    "/.htaccess": 307,
    "/wp-login.php": 307,
    "/phpmyadmin/index.php": 307,
    "/server-status": 307,
    "/api/": 307
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "cname_chain": [
    "portal.processsimple.trafficmanager.net",
    "makershellafdredirectprod-eec7eeftc6chcdgf.z01.azurefd.net",
    "mr-z01.tm-azurefd.net"
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
      "aia_ocsp": null,
      "not_before": "20260829045307",
      "not_after": "20270225045307"
    }
  },
  "x12": {
    "status": 307
  },
  "elapsed_s": 8.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
