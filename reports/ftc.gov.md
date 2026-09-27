# Security Audit Report — ftc.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ftc.gov/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | ftc.gov |
| Test date | 2026-09-27 02:30 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 4, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 20 | info | HTML10 | Plaintext email addresses in the document | CWE-200 |
| 21 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 22 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 23 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=93600
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 9. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=VemqQV9Hiv6MzI1B0hzhRq4mlC2mVvs5qUUog19MRso; cisco-ci-domain-verification=25cadc1688da051ffa2539c464e864ec4aaefd22a584a0251e9; adobe-sign-verification=6aef5f85dec2584b6bd8bc23abb2418c2fd5746c6b72586f884b9830
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://status.geotrust.com -> http-200
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 184.50.180.40 carries PTR a184-50-180-40.deploy.static.akamaitechnologies.com. for ftc.gov.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkpwm69tjn2dw6.html -> 403; error page/headers match: Akamai.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for ftc.gov, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on ftc.gov has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of ftc.gov.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 20. [INFO] Plaintext email addresses in the document (`HTML10`)

- **CWE:** CWE-200
- **Detail:** Root document of ftc.gov contains 1 plaintext email address(es) (e.g. pwh-alert@ftc.gov); these are harvestable by bots.
- **Recommendation:** Use a contact form or mailto obfuscation for non-critical addresses.

### 21. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of ftc.gov carries alt-svc h3=":443"; ma=93600; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 22. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on ftc.gov identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 23. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of ftc.gov is http://status.geotrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "ftc.gov",
  "dns": {
    "a": [
      "184.50.180.40"
    ],
    "aaaa": [
      "2600:1417:76:4a0::2031",
      "2600:1417:76:4a1::2031"
    ],
    "cname": null,
    "mx": [
      "ftc-gov.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "a6-66.akam.net.",
      "a3-65.akam.net.",
      "a26-64.akam.net.",
      "a1-252.akam.net.",
      "a24-67.akam.net.",
      "a7-67.akam.net."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=VemqQV9Hiv6MzI1B0hzhRq4mlC2mVvs5qUUog19MRso",
      "ab+sBVXiIC82wNktOPIy6RX8agj5Evkxyo85mpdxHboRO0smOB8QUksAASKBEFW1yz9vbMdeFb6kz3GkyshW+g==",
      "cisco-ci-domain-verification=25cadc1688da051ffa2539c464e864ec4aaefd22a584a0251e9a7b769df530bf",
      "adobe-sign-verification=6aef5f85dec2584b6bd8bc23abb2418c2fd5746c6b72586f884b983098370e38",
      "NzWLUncbdZVFeNNXMttXmWGCtTfPC610lVN0DG4twtsHL/fF6nVZ55r7BqRBAwnrzb076GaeoI+KR/D688HhEw==",
      "facebook-domain-verification=i064e2y03lievnt3ubarreperwg6mf",
      "apple-domain-verification=yDCeSJ81y3pXRCi0",
      "dwgyAlEH+VVQ4N58bmeEgHt3HhajTjhhUm+VEY/orFKBEvH2dcjCEBgIw9usDqvfE4etnbgRlB9RalHvcPraVg==",
      "v=spf1 mx include:spf1.ftc.gov include:spf2.ftc.gov -all",
      "identrust_validate=AW6O5chGVEhxWmmFGKoMLN8DZRwEsR4bmAtOrkHPfkc9",
      "adobe-idp-site-verification=a832eee07863ffdf3f5fdfc757918cff06c414cc6426d443d893f7e4740ac4f4",
      "hpe-greenlake-domain-verification=6f677033714443654164395339726174365a7544727047374e74545068636837",
      "identrust_validate=ba+DUU6G9a65f8A1q6tau3K4bx5bi/29LZlwh82DrgPG",
      "MS=ms80119051",
      "_a2ac2792i79twzh20o9uow3xf2g61d4",
      "MS=ms26536772"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:reports@dmarc.cyber.dhs.gov, mailto:dmarcemails@ftc.gov; ruf=mailto:dmarcemails@ftc.gov; rf=afrf; pct=100; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=District of Columbia, localityName=Washington, organizationName=Federal Trade Commission, commonName=www.ftc.gov",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Feb  9 00:00:00 2026 GMT",
    "notAfter": "Feb  8 23:59:59 2027 GMT",
    "san": [
      "www.ftc.gov",
      "alertaenlinea.gov",
      "bulkorder.ftc.gov",
      "bulkorder2.ftc.gov",
      "business.ftc.gov",
      "consumer.ftc.gov",
      "consumer.gov",
      "consumidor.ftc.gov",
      "consumidor.gov",
      "dontserveteens.gov",
      "edit.bulkorder.ftc.gov",
      "edit.consumer.ftc.gov",
      "edit.consumer.gov",
      "edit.ftc.gov",
      "edit.militaryconsumer.gov",
      "edit.staging.ftc.gov",
      "ftc.gov",
      "hsr.gov",
      "loadtest.ftc.gov",
      "military.consumer.gov",
      "militaryconsumer.gov",
      "oig.ftc.gov",
      "onguardonline.gov",
      "search.ftc.gov",
      "staging.bulkorder.ftc.gov",
      "staging.consumer.ftc.gov",
      "staging.consumer.gov",
      "staging.ftc.gov",
      "staging.militaryconsumer.gov",
      "www.alertaenlinea.gov",
      "www.bulkorder.ftc.gov",
      "www.business.ftc.gov",
      "www.consumer.ftc.gov",
      "www.consumer.gov",
      "www.consumidor.ftc.gov",
      "www.consumidor.gov",
      "www.dontserveteens.gov",
      "www.hsr.gov",
      "www.military.consumer.gov",
      "www.militaryconsumer.gov",
      "www.onguardonline.gov"
    ],
    "days_left": 134,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "184.50.180.40",
    "open": []
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ftc.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=VemqQV9Hiv6MzI1B0hzhRq4mlC2mVvs5qUUog19MRso",
    "cisco-ci-domain-verification=25cadc1688da051ffa2539c464e864ec4aaefd22a584a0251e9",
    "adobe-sign-verification=6aef5f85dec2584b6bd8bc23abb2418c2fd5746c6b72586f884b9830",
    "facebook-domain-verification=i064e2y03lievnt3ubarreperwg6mf",
    "apple-domain-verification=yDCeSJ81y3pXRCi0"
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
      "aia_ocsp": "http://status.geotrust.com",
      "serial": 19450714032113671453668644277575311327,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl"
      ],
      "san": [
        "www.ftc.gov",
        "alertaenlinea.gov",
        "bulkorder.ftc.gov",
        "bulkorder2.ftc.gov",
        "business.ftc.gov",
        "consumer.ftc.gov",
        "consumer.gov",
        "consumidor.ftc.gov",
        "consumidor.gov",
        "dontserveteens.gov",
        "edit.bulkorder.ftc.gov",
        "edit.consumer.ftc.gov",
        "edit.consumer.gov",
        "edit.ftc.gov",
        "edit.militaryconsumer.gov",
        "edit.staging.ftc.gov",
        "ftc.gov",
        "hsr.gov",
        "loadtest.ftc.gov",
        "military.consumer.gov"
      ],
      "subject_dn": "310b3009060355040613025553311d301b060355040813144469737472696374206f6620436f6c756d626961311330110603550407130a57617368696e67746f6e3121301f060355040a13184665646572616c20547261646520436f6d6d697373696f6e311430120603550403130b7777772e6674632e676f76",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311f301d0603550403131647656f547275737420544c5320525341204341204731",
      "not_before": "20260209000000",
      "not_after": "20270208235959"
    },
    "ocsp": "http-200"
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 403,
    "ptr": [
      "a184-50-180-40.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 403,
    "http_status": 403,
    "p404_status": 403,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 403,
    "hsts": "max-age=31536000 ; preload",
    "crl": {
      "url": "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 403
  },
  "x16": {
    "root_status": 403,
    "alt_svc": "h3=\":443\"; ma=93600",
    "cdn": [
      "Akamai"
    ]
  },
  "x17": {
    "ocsp_http": "http://status.geotrust.com"
  },
  "elapsed_s": 9.5,
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
