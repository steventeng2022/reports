# Security Audit Report — united.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://united.com/ |
| Bug bounty program | United Airlines |
| Listed scope domain | united.com |
| Test date | 2026-09-27 02:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
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
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 17 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 18 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15768000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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
- **Detail:** Apex TXT records with verification/token content: vmware-cloud-verification-9cd123ef-b219-486d-a9a0-b315b5ba0da3; webexdomainverification.NMB6=5e3a4841-bed2-49e3-995e-7e6577637d4a; webexdomainverification.=c3b585c2-1a13-47c5-abc9-49cebb862ae3
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.209.216.114 carries PTR a23-209-216-114.deploy.static.akamaitechnologies.com. for united.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for united.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on united.com identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 18. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of united.com is http://status.geotrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "united.com",
  "dns": {
    "a": [
      "23.209.216.114"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "67.231.145.22 (pref 5)",
      "mxa-00212602.gslb.pphosted.com (pref 10)",
      "mxb-00212602.gslb.pphosted.com (pref 10)",
      "67.231.152.135 (pref 6)"
    ],
    "ns": [
      "a11-66.akam.net.",
      "a1-66.akam.net.",
      "a10-65.akam.net.",
      "a18-67.akam.net.",
      "a5-65.akam.net.",
      "a26-64.akam.net."
    ],
    "caa": [],
    "spf": [
      "ibmid=775b7bb2-5029-4241-8adb-c97959b13265",
      "insomnia-validation=7975158d8fce4d6c9e6889f06d4894d5c0e9e9e6e7985e37865960ac45e99c60",
      "vmware-cloud-verification-9cd123ef-b219-486d-a9a0-b315b5ba0da3",
      "pardot895221=5106e47e334be87ed949b11dd8839ee745c0b5f2d9c49d4d7268519ee605ad84",
      "_pu9ae99ovdbyxleilm1jlqdhzbmmcv5",
      "webexdomainverification.NMB6=5e3a4841-bed2-49e3-995e-7e6577637d4a",
      "webexdomainverification.=c3b585c2-1a13-47c5-abc9-49cebb862ae3",
      "3hdk90qzhvh0l7yvw0wg014c6m2xxz9d",
      "vmware-cloud-verification-21e81564-6cf2-4948-92cd-7d169a06dbfd",
      "pardot895221=e613bb2bd7a53de50e4c0f525dca606bba246e4d5fc9514a220acf78f6b40cd2",
      "e2ma-verification=vozeb",
      "starlink-domain-verification=c05d3ac0-aef3-4c4a-a5a2-d2310fb2422b",
      "_globalsign-domain-verification=2wRqY6IrIINLY7B8Qcp-qur9HsiRTO04g4gwsMmFy3",
      "smartsheet-site-validation=a-QJqDk8-xugCQsJJ59BloRXsQ78NHEu",
      "google-gws-recovery-domain-verification=47260811",
      "duo_sso_verification=DhdWOQSIwy1C7mfnQgxNMBEtJM5SbFCu5mbQ8jKQCh4LGxf6CmNJlx1NUMEFrro1",
      "e2ma-verification=so1eb",
      "ciUNjcPdDUwJlNwxs7hQOL+JdXldzfLl1U0+1NLC4U/KcgyYha7rJDX0z8ECmAXiC7WfSIWGNLcakbS5aicncg==",
      "sending_domain473072=2536efd81f433897e4eade7bd5c07c9f572003ea06fcdee11f2872c01a4befbf",
      "MS=ms48035785",
      "pardot895221=fa7d573afba39e23c5d310777b3e4b8e3059fc036c5f8a141061e48acb644c2e",
      "atlassian-domain-verification=LS4NFLIjbXxDhEDh1uRXHFIsGV0c7/eMwPLjJasBzHbldYDoiaVCRUUJ19njM5b/",
      "google-site-verification=o8Ds49E6OUh_KlAGHKP5Cp1n2VFnRCOn0Po9XIYNuVw",
      "cisco-ci-domain-verification=150e1a1fbae294ccdb82094631861d593dd76e186d81076c716c15de04b1b04e",
      "docusign=83f7c0a0-80c9-41e2-9dbb-101c34f5fd08",
      "qFCoTGARAo0YzsD8J4JXGTPJnoGyXVcN1UUT76knKhsb0VWg5k8Ltz0EKn5Wht7bsSdnw7/DP8N0lC4BPHOutQ==",
      "anthropic-domain-verification-9jtz5g=oedRjF26denAvMXx0Ubb50D74",
      "miro-verification=c4f22d27f3df65dc4bcc76cdacabb97da8a5765e",
      "Dynatrace-site-verification=5aa9bae5-aed4-4063-8545-7f63572d80ff__3j2g8rj4tmvasq9qhrv51ichkd",
      "TSqI+8N8XlipHXL0ef29pOHU8OuiMLGRBHCe/Bj9pnVXi4+pFDDuyU7cAs0mRED85RC60Vk/RQk/UE+o+Qe3dw==",
      "hpe-greenlake-domain-verification=4a774d567170674c43373938696b56704239656c347a533862435a66356b4455",
      "adobe-idp-site-verification=4b5fa402a6cdc780157d690e7860970f4447772807197ddf38cbc78d7b3666d6",
      "_7d3owcum7npdansxr9rm5adumrqels5",
      "zoho-verification=zb79381715.zmverify.zoho.in",
      "pardot895221=0283c9002444941b4251d2fc11749bba12b56a77f8f1fcafcae8f8ea396db336",
      "rebelmouse=0296577248d0df8680XXXXb4f5b2663e106f6c40",
      "cloudhealth=5dda028a-3bad-41ee-8197-a76d049e4648",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "mandrill_verify.o-YnntrhVJmYGforpN1_eg",
      "e2ma-verification=l59eb",
      "apple-domain-verification=JX4d4nEINvrmcrFB",
      "_f4a7xelp84p4m660f9cr1t61ryb6n3f",
      "cisco-ci-domain-verification=7b72a7a0f463b7ae34bd19b2b4e7c9e32a23184af97a606601ab4470cbb94b67",
      "twilio-domain-verification=422291df00dd2d1e86b024d9d140c96f",
      "docker-verification=eac5f372-ff38-49a3-a449-013649023462",
      "sitecore-domain-verification=544b04b1172546a8ad8a86742156828e",
      "e2ma-verification=wozeb",
      "cisco-ci-domain-verification=2348f9b423234f5b6cb296d8e0b21a433c9708dbd7885f35a347b7f361eef8e6",
      "EjEnj26GQ6Rch4cK-0_3Bg",
      "docusign=a852ec83-5d46-4c48-9ae4-35ac3ae4b32c",
      "e2ma-verification=to1eb"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; pct=100; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=Illinois, localityName=Arlington Heights, organizationName=United Airlines Inc, commonName=www.united.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Dec  9 00:00:00 2025 GMT",
    "notAfter": "Dec  8 23:59:59 2026 GMT",
    "san": [
      "www.united.com",
      "beta.united.com",
      "checkin.united.com",
      "ife.unitedwifi.com",
      "mobile.united.com",
      "pss.united.com",
      "ual.com",
      "united.com",
      "unitedairlines.ca",
      "unitedairlines.co.uk",
      "unitedairlines.com",
      "unitedairlines.jp",
      "unitedwifi.com",
      "walletservices.united.com",
      "www.ual.com",
      "www.unitedairlines.ca",
      "www.unitedairlines.co.uk",
      "www.unitedairlines.com",
      "www.unitedairlines.de",
      "www.unitedairlines.jp",
      "www.unitedwifi.com"
    ],
    "days_left": 72,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.216.114",
    "open": []
  },
  "https": {
    "status": 302,
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
      "origin": "https://sub.united.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://united.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "vmware-cloud-verification-9cd123ef-b219-486d-a9a0-b315b5ba0da3",
    "webexdomainverification.NMB6=5e3a4841-bed2-49e3-995e-7e6577637d4a",
    "webexdomainverification.=c3b585c2-1a13-47c5-abc9-49cebb862ae3",
    "vmware-cloud-verification-21e81564-6cf2-4948-92cd-7d169a06dbfd",
    "e2ma-verification=vozeb"
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
      "serial": 7965685672892962398079613461689470801,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl"
      ],
      "san": [
        "www.united.com",
        "beta.united.com",
        "checkin.united.com",
        "ife.unitedwifi.com",
        "mobile.united.com",
        "pss.united.com",
        "ual.com",
        "united.com",
        "unitedairlines.ca",
        "unitedairlines.co.uk",
        "unitedairlines.com",
        "unitedairlines.jp",
        "unitedwifi.com",
        "walletservices.united.com",
        "www.ual.com",
        "www.unitedairlines.ca",
        "www.unitedairlines.co.uk",
        "www.unitedairlines.com",
        "www.unitedairlines.de",
        "www.unitedairlines.jp"
      ],
      "subject_dn": "310b30090603550406130255533111300f06035504081308496c6c696e6f6973311a30180603550407131141726c696e67746f6e2048656967687473311c301a060355040a1313556e69746564204169726c696e657320496e63311730150603550403130e7777772e756e697465642e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311f301d0603550403131647656f547275737420544c5320525341204341204731",
      "not_before": "20251209000000",
      "not_after": "20261208235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 302,
    "ptr": [
      "a23-209-216-114.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://www.united.com/",
    "http_status": 301,
    "p404_status": 302,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "hsts": "max-age=15768000; preload",
    "crl": {
      "url": "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 302
  },
  "x16": {
    "root_status": 302,
    "cdn": [
      "Akamai"
    ]
  },
  "x17": {
    "ocsp_http": "http://status.geotrust.com"
  },
  "elapsed_s": 10.5,
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
