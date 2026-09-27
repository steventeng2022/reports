# Security Audit Report — homedepot.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://homedepot.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | homedepot.com |
| Test date | 2026-09-27 02:33 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 5, Info: 19)

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
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 20 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 21 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 22 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 23 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 24 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 21 days (notAfter Oct 18 23:59:59 2026 GMT).
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
- **Detail:** Apex TXT records with verification/token content: bv-domain-verification=e51f90f4244f97973230f42f1a8485fc03995b331b6a856ee883e7262; onetrust-domain-verification=9be9c479e03f424d939ac18286224476; google-site-verification=dtvgbq00CxnP6nJC7dgLEOVtLcoKKXtdj90AImFCbuM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 35.201.95.83 carries PTR 83.95.201.35.bc.googleusercontent.com. for homedepot.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for homedepot.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The homedepot.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on homedepot.com is 'nginx/1.31.1' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 21. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of homedepot.com carries alt-svc h3=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 22. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of homedepot.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 23. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of homedepot.com discloses a 1-hop fronting chain (1.1 google); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 24. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of homedepot.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

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
      "exchanger2.homedepot.com (pref 30)",
      "mxa-000e6608.gslb.pphosted.com (pref 10)",
      "mx0a-000e6608.pphosted.com (pref 20)",
      "exchanger1.homedepot.com (pref 30)",
      "mx0b-000e6608.pphosted.com (pref 20)",
      "mxb-000e6608.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "a18-67.akam.net.",
      "a3-64.akam.net.",
      "a7-66.akam.net.",
      "a1-27.akam.net.",
      "a16-66.akam.net.",
      "a6-65.akam.net."
    ],
    "caa": [],
    "spf": [
      "bv-domain-verification=e51f90f4244f97973230f42f1a8485fc03995b331b6a856ee883e72624c85d3d",
      "onetrust-domain-verification=9be9c479e03f424d939ac18286224476",
      "google-site-verification=dtvgbq00CxnP6nJC7dgLEOVtLcoKKXtdj90AImFCbuM",
      "adobe-idp-site-verification=3fbd7a09e2fe24031aad0a4a8c68e8242e227010cef9e40aeebcf4bc7addb8a0",
      "astro-domain-verification=cmqshn0vh1hv101nynj90s660",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ip4:148.163.149.217 ip4:148.163.153.207 include:mail.zendesk.com ~all",
      "18aa0eb980e5432c9ac85035050b628",
      "smartsheet-site-validation=UQZXQ9whIKMhr-lD3a9QxQbUGhnacn2o",
      "b93b75bb-c0c7-445c-89eb-8560cef8dba9",
      "ms-domain-verification=3a3a542a-71c8-45ad-ab04-7152bfba2a64",
      "Dynatrace-site-verification=5218cc8f-b799-466b-81e2-151902ea9493__b7hius6gka10pcd61m5vcgio0c",
      "hj-ownership=a4r4Ms7CqBFe1WU",
      "pardot757373=218869be8ba439583983ba0ae0f7bfe67956ead606a3deb3f20bdfc1fd42b8cd",
      "google-site-verification=3NvwcCmI2tiaqvhxEx918MCg-AfY9OOwxB3NpSQwTjw.",
      "mk-org-sso-967a2df0-7b8d-405b-b414-4627a3d6311e",
      "liveramp-site-verification=C7ahcr0qXYCzwhdiK-pcYbtLNhwzEvcgbvbgjovyRy0",
      "atlassian-domain-verification=xqfqkDq+B7CyObHlKTiLqquR1QTlpKQeek64YJoRwFWeUm0Tihwqz8GA0enUIHSs",
      "vmware-cloud-verification-e1ffc876-3a8b-4242-94c1-9e8db12d03f1",
      "OSIAGENTREGURL=https://mdm.homedepot.com/athena/enrollment/athenaiosenroll.aspx",
      "ms-domain-verification=1851d99d-d9bb-4eb8-b800-8e86a71b0fcc",
      "pendo-domain-verification=6163daa5-67e0-4c5d-9607-d97d6a0c9ab4",
      "google-site-verification=wpZpi9YRPHBYFY7AfQOaVZSOnXuiN_LYpOsuCJRiEyQ",
      "ciscocidomainverification=2a19d56e7ed441cd6cd10c84d904c0f8828fba1455df76c984284b5d85fa5c2e",
      "google-site-verification=94tM-sDACvy_JNGSU6fp8GOaI6k5OuzXZN8PPYCtdRI"
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
    "days_left": 21,
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
    "onetrust-domain-verification=9be9c479e03f424d939ac18286224476",
    "google-site-verification=dtvgbq00CxnP6nJC7dgLEOVtLcoKKXtdj90AImFCbuM",
    "adobe-idp-site-verification=3fbd7a09e2fe24031aad0a4a8c68e8242e227010cef9e40aeebc",
    "astro-domain-verification=cmqshn0vh1hv101nynj90s660"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 16840587046700445931263230830957993881,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "homedepot.com"
      ],
      "subject_dn": "310b30090603550406130255533110300e0603550408130747656f726769613110300e0603550407130741746c616e7461311d301b060355040a131454686520486f6d65204465706f742c20496e632e311630140603550403130d686f6d656465706f742e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260403000000",
      "not_after": "20261018235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "83.95.201.35.bc.googleusercontent.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.homedepot.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "alt_svc": "h3=\":443\"; ma=2592000"
  },
  "x17": {
    "ocsp_http": "http://ocsp.digicert.com",
    "via": "1.1 google"
  },
  "elapsed_s": 18.5,
  "rechecked": "2026-09-27 02:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
