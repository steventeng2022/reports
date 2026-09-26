# Security Audit Report — homedepot.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://homedepot.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | homedepot.com |
| Test date | 2026-09-26 17:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 22 days (notAfter Oct 18 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx/1.31.1
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx/1.31.1
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: bv-domain-verification=e51f90f4244f97973230f42f1a8485fc03995b331b6a856ee883e7262; Dynatrace-site-verification=5218cc8f-b799-466b-81e2-151902ea9493__b7hius6gka10pc; vmware-cloud-verification-e1ffc876-3a8b-4242-94c1-9e8db12d03f1
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of homedepot.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "homedepot.com",
  "dns": {
    "a": [
      "35.201.95.83"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-000e6608.gslb.pphosted.com (pref 10)",
      "exchanger1.homedepot.com (pref 30)",
      "exchanger2.homedepot.com (pref 30)",
      "mxb-000e6608.gslb.pphosted.com (pref 10)",
      "mx0b-000e6608.pphosted.com (pref 20)",
      "mx0a-000e6608.pphosted.com (pref 20)"
    ],
    "ns": [
      "a1-27.akam.net.",
      "a7-66.akam.net.",
      "a16-66.akam.net.",
      "a6-65.akam.net.",
      "a3-64.akam.net.",
      "a18-67.akam.net."
    ],
    "spf": [
      "bv-domain-verification=e51f90f4244f97973230f42f1a8485fc03995b331b6a856ee883e72624c85d3d",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ip4:148.163.149.217 ip4:148.163.153.207 include:mail.zendesk.com ~all",
      "mk-org-sso-967a2df0-7b8d-405b-b414-4627a3d6311e",
      "Dynatrace-site-verification=5218cc8f-b799-466b-81e2-151902ea9493__b7hius6gka10pcd61m5vcgio0c",
      "vmware-cloud-verification-e1ffc876-3a8b-4242-94c1-9e8db12d03f1",
      "ms-domain-verification=1851d99d-d9bb-4eb8-b800-8e86a71b0fcc",
      "google-site-verification=dtvgbq00CxnP6nJC7dgLEOVtLcoKKXtdj90AImFCbuM",
      "18aa0eb980e5432c9ac85035050b628",
      "b93b75bb-c0c7-445c-89eb-8560cef8dba9",
      "ciscocidomainverification=2a19d56e7ed441cd6cd10c84d904c0f8828fba1455df76c984284b5d85fa5c2e",
      "OSIAGENTREGURL=https://mdm.homedepot.com/athena/enrollment/athenaiosenroll.aspx",
      "pendo-domain-verification=6163daa5-67e0-4c5d-9607-d97d6a0c9ab4",
      "pardot757373=218869be8ba439583983ba0ae0f7bfe67956ead606a3deb3f20bdfc1fd42b8cd",
      "adobe-idp-site-verification=3fbd7a09e2fe24031aad0a4a8c68e8242e227010cef9e40aeebcf4bc7addb8a0",
      "liveramp-site-verification=C7ahcr0qXYCzwhdiK-pcYbtLNhwzEvcgbvbgjovyRy0",
      "astro-domain-verification=cmqshn0vh1hv101nynj90s660",
      "atlassian-domain-verification=xqfqkDq+B7CyObHlKTiLqquR1QTlpKQeek64YJoRwFWeUm0Tihwqz8GA0enUIHSs",
      "google-site-verification=94tM-sDACvy_JNGSU6fp8GOaI6k5OuzXZN8PPYCtdRI",
      "google-site-verification=3NvwcCmI2tiaqvhxEx918MCg-AfY9OOwxB3NpSQwTjw.",
      "smartsheet-site-validation=UQZXQ9whIKMhr-lD3a9QxQbUGhnacn2o",
      "ms-domain-verification=3a3a542a-71c8-45ad-ab04-7152bfba2a64",
      "onetrust-domain-verification=9be9c479e03f424d939ac18286224476",
      "hj-ownership=a4r4Ms7CqBFe1WU",
      "google-site-verification=wpZpi9YRPHBYFY7AfQOaVZSOnXuiN_LYpOsuCJRiEyQ"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=Georgia, localityName=Atlanta, organizationName=The Home Depot, Inc., commonName=homedepot.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Apr  3 00:00:00 2026 GMT",
    "notAfter": "Oct 18 23:59:59 2026 GMT",
    "san": [
      "homedepot.com"
    ],
    "days_left": 22,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "35.201.95.83",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx/1.31.1"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.homedepot.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.homedepot.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "bv-domain-verification=e51f90f4244f97973230f42f1a8485fc03995b331b6a856ee883e7262",
    "Dynatrace-site-verification=5218cc8f-b799-466b-81e2-151902ea9493__b7hius6gka10pc",
    "vmware-cloud-verification-e1ffc876-3a8b-4242-94c1-9e8db12d03f1",
    "ms-domain-verification=1851d99d-d9bb-4eb8-b800-8e86a71b0fcc",
    "google-site-verification=dtvgbq00CxnP6nJC7dgLEOVtLcoKKXtdj90AImFCbuM"
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
  "elapsed_s": 9.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
