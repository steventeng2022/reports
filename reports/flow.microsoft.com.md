# Security Audit Report — flow.microsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://flow.microsoft.com/ |
| Bug bounty program | Microsoft Online Services |
| Listed scope domain | flow.microsoft.com |
| Test date | 2026-09-27 02:29 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 5, Info: 9)

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
| 10 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 11 | low | RD2 | HTTPS root redirects to a different domain | CWE-200 |
| 12 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 13 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 14 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

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

### 10. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://oneocsp.microsoft.com/ocsp -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 11. [LOW] HTTPS root redirects to a different domain (`RD2`)

- **CWE:** CWE-200
- **Detail:** https://flow.microsoft.com/ answered 307 with Location: https://make.powerautomate.com/ (cross-domain handoff at the entry point).
- **Recommendation:** Review the cross-domain redirect; it discloses the real entry point and can be abused in open-redirect-style flows.

### 12. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on flow.microsoft.com identify the edge as Azure Front Door / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 13. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of flow.microsoft.com contains wildcard SAN entry(ies) *.asia.flow.microsoft.com, *.australia.flow.microsoft.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 14. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of flow.microsoft.com is http://oneocsp.microsoft.com/ocsp; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "flow.microsoft.com",
  "dns": {
    "a": [
      "150.171.110.70"
    ],
    "aaaa": [
      "2603:1061:14:141::1"
    ],
    "cname": "portal.processsimple.trafficmanager.net.",
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
    "ip": "150.171.110.70",
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
      "aia_ocsp": "http://oneocsp.microsoft.com/ocsp",
      "serial": 1895631766139269533334609286179248750943868081,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://www.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2016_Partition00053.crl",
        "http://crl2.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2016_Partition00053.crl"
      ],
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
        "*.australia.flow.microsoft.com"
      ],
      "subject_dn": "310b3009060355040613025553310b30090603550408130257413110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e311b301906035504031312666c6f772e6d6963726f736f66742e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312830260603550403131f4d6963726f736f667420544c5320473220525341204341204f435350203136",
      "not_before": "20260829045307",
      "not_after": "20270225045307"
    },
    "ocsp": "http-400"
  },
  "x12": {
    "status": 307
  },
  "x13": {
    "root_status": 307,
    "root_location": "https://make.powerautomate.com/",
    "http_status": 307,
    "p404_status": 307,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 307,
    "crl": {
      "url": "http://www.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2016_Partition00053.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 307
  },
  "x16": {
    "root_status": 307,
    "cdn": [
      "Azure Front Door",
      "Fastly"
    ]
  },
  "x17": {
    "wildcard_san": [
      "*.asia.flow.microsoft.com",
      "*.australia.flow.microsoft.com"
    ],
    "ocsp_http": "http://oneocsp.microsoft.com/ocsp"
  },
  "elapsed_s": 6.3,
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
