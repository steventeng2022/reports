# Security Audit Report — salesforce.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://salesforce.com/ |
| Bug bounty program | Salesforce |
| Listed scope domain | salesforce.com |
| Test date | 2026-09-27 02:43 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 3, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 15 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=OXivRKiSmufeLZHqZHxzvbEU_LFMiy4XwYtJiSS1BhQ; remarkable-domain-verification=394b7d94-d630-4c40-ac32-413a38622f73; canva-site-verification=_abffN3m74Bc2XZ_68lccw
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 104.109.10.129 carries PTR a104-109-10-129.deploy.static.akamaitechnologies.com. for salesforce.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 15. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on salesforce.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for salesforce.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on salesforce.com identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 18. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of salesforce.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "salesforce.com",
  "dns": {
    "a": [
      "104.109.10.129",
      "23.1.99.130",
      "184.25.179.132",
      "23.1.35.132",
      "104.109.11.129",
      "23.1.106.133",
      "184.31.3.130",
      "184.31.10.133"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-00177002.gslb.pphosted.com (pref 10)",
      "mxa-00177002.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "pch2.salesforce-dns.com.",
      "udns3.salesforce.com.",
      "pch1.salesforce-dns.com.",
      "udns4.salesforce.com.",
      "udns1.salesforce.com.",
      "udns2.salesforce.com."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=OXivRKiSmufeLZHqZHxzvbEU_LFMiy4XwYtJiSS1BhQ",
      "remarkable-domain-verification=394b7d94-d630-4c40-ac32-413a38622f73",
      "DirectFedAuthUrl=https://salesforce.okta.com/app/salesforce_pwcidentitypro_1/exk12ojlg6rjhBkTY698/sso/saml",
      "canva-site-verification=_abffN3m74Bc2XZ_68lccw",
      "google-site-verification=h5tEfIPH1oMV9hxvFY7mWCS870JmVhm-bpbKTTg5L4A",
      "pardot220122=922f8d6c355d7ff72ed3e771a2eca71656d0249cfdc70a8cebb481d367d6f006",
      "stripe-verification=92ed39e34d3d3361667499947254c2fe1e02c212ca373bf11734c1423133dcfe",
      "mixpanel-domain-verify=f2151de7-1e89-41b1-8968-b7cdd8df6740",
      "google-site-verification=XHgruaJj29eI7YjqDkEWZivuT0wlakIWgB2N4DRa_QM",
      "00DF0000000gZsuMAE",
      "hubspot-developer-verification=YjRkOWExNDAtM2JjZS00YWQ0LWExNzItMGVkYzljMDEwM2M3",
      "vmware-cloud-verification-edb072dd-c0ed-478e-a55f-1aa17364e617",
      "atlassian-domain-verification=vTF7JaBo8Jpp/uhUFDPztkIr5aildFzbq9aLIcBbwK5aIdI9s8WQRGPTnKRONIiM",
      "neat-pulse-domain-verification-zDvG1kM=5074fe39-a4bb-479e-9018-9ef1878fd2f1",
      "liveramp-site-verification=EIEl6MgS2nOv3dKtxxVir8tWpKE85lmKSh2s7wGwE4w",
      "pardot1=6eae4d5ab80fc91a64539164ab421392a58d97551b230b12152dffb7553ea905",
      "google-site-verification=D6BlHxqITDdvcLDrxA3_ltYf9P3rRxm8AKKNT3rk4W8",
      "google-site-verification=HV79FO1Y0siBF9WSte-fAOzLI3om9c1V08sBXq2p39M",
      "hcp-domain-verification=92c617d35c9102aa0d57a73ea5894ce0a593b2ec34bb05486eeb69f6ef15f7fd",
      "stripe-verification=9ca4e73f9b5286bdcdbd5b91f97ad519544e5ee56eebb2f2dc6b48dbec579fe0",
      "stripe-verification=7a979e02f78e0a07950be0a127275cc4866db0a196913cfceaaa8035b8dbf959",
      "zoom-domain-verification=ZOOM_verify_d9d75d3013184f4ba571502ca24dfaf6",
      "00DF0000000gZsumae",
      "zoom-domain-verification=ZOOM_verify_6429ec4f4e4f49e58350c473496f0f18",
      "DirectFedAuthUrl=https://salesforce.okta.com/app/salesforce_w19107268_1/exky1kgawwTUSZCb2697/sso/saml",
      "sending_domain182062=ecf3eec4d6ebcf61c5f77be11dffd322fd0f57d8d10fc75c7ae07ffc21d427a7",
      "tiktok-developers-site-verification=6SG6XJHEtcx9rqix8FICiM4RxxkC4g1L",
      "SFMC-cGJQFeEomoQQt-tQ3c_QXefdwzOGuj_Tjl4oWwrW",
      "cloudhealth=7fe179e6-9085-4d4a-b2cd-eeb11f0c2468",
      "docker-verification=b238c187-0eb6-4710-ac1f-0d2ed19765b5",
      "google-site-verification=AF6Xx_zcM9CpPWi0iT5dSiHH05tVgT3Gr2ERgAZ0-m0",
      "5/1ESlGdIH/mwCF+T9SOo3PjURgk0lqakv0VJ8er4Ss=",
      "stripe-verification=B20840C7B159BD229B805ABB54423AE52404E97B4697AA9C23ECF43BA3E8BC37",
      "sending_domain373542=845254d896ac5dfad0d6494e4908a8b6a5e057fdcce30d211eebadeb6b4e87cc",
      "notion-domain-verification=Lh3bZWCwAyG9KMR88UmcLLXPlUj4eIud9Gp4gf85VGJ",
      "1password-site-verification=IIVOBJGQRBCNTB3RNSU7CCAFQY",
      "google-site-verification=YWwSjixMcFJ1lVJe2XyMsPgFOe8E5vaW6xV-pVmxQQs",
      "jamf-site-verification=6VMo4NqTt2upSV1B7wb8sw",
      "v=spf1 include:_spf.google.com include:_spf.salesforce.com exists:%{i}._spf.corp.salesforce.com ~all",
      "google-site-verification=AgWPJ-RJmfrnOtIUUO5mTFDFVNb5XJPAJAUduwbF9PE"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;fo=1:d:s;pct=100;rua=mailto:dmarc_agg@vali.email,mailto:0e5a5c34@inbox.ondmarc.com;ruf=mailto:0e5a5c34@inbox.ondmarc.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Salesforce, Inc., commonName=salesforce.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Sep 23 00:00:00 2026 GMT",
    "notAfter": "Apr  9 23:59:59 2027 GMT",
    "san": [
      "salesforce.com",
      "agentblazer.com",
      "askmoreof.ai",
      "askmoreofai.com",
      "assistly.com",
      "atonit.com.br",
      "atonit.digital",
      "attic.io",
      "buddymedia.com",
      "chatter.com",
      "chatter.salesforce.com",
      "clicksoftware.com",
      "cloudconnect.com",
      "cloudcraze.com",
      "cotweet.com",
      "credentialmaster.com",
      "demandware.com",
      "desk.com",
      "documentforce.com",
      "dreamforce.com",
      "einstein.com",
      "force.com",
      "govforce.com",
      "gravitytank.com",
      "griddable.io",
      "heywire.com",
      "leveljump.io",
      "leveljumpsoftware.com",
      "mapanything.com",
      "marketingcloud.com",
      "mobify.com",
      "pardot.com",
      "quotable.com",
      "radian6.com",
      "salesblazer.com",
      "salesforce.de",
      "salesforceconnections.com",
      "salesforcemarketingcloud.com",
      "sequence.com",
      "serviceblazer.com",
      "sfdcstatic.com",
      "sforce.com",
      "site.com",
      "social.com",
      "steelbrick.com",
      "toopher.com",
      "tractionondemand.com",
      "trailheadx.com",
      "twinprime.com",
      "vaccinecloud.com",
      "vlocity.app",
      "vlocity.ch",
      "vlocity.com",
      "vlocity.de",
      "vlocity.fr",
      "vlocity.in",
      "vlocity.info",
      "vlocity.io",
      "vlocity.it",
      "vlocity.me",
      "vlocity.nl",
      "vlocity.online",
      "vlocity.pl",
      "vlocity.software",
      "vlocity.solutions",
      "vlocity.tech",
      "vlocity.technology",
      "vlocity.us",
      "weinvoiceit.com"
    ],
    "days_left": 194,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.109.10.129",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.salesforce.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://salesforce.com/"
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
    "google-site-verification=OXivRKiSmufeLZHqZHxzvbEU_LFMiy4XwYtJiSS1BhQ",
    "remarkable-domain-verification=394b7d94-d630-4c40-ac32-413a38622f73",
    "canva-site-verification=_abffN3m74Bc2XZ_68lccw",
    "google-site-verification=h5tEfIPH1oMV9hxvFY7mWCS870JmVhm-bpbKTTg5L4A",
    "stripe-verification=92ed39e34d3d3361667499947254c2fe1e02c212ca373bf11734c1423133"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 7510292102799623342239346271537050466,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "salesforce.com",
        "agentblazer.com",
        "askmoreof.ai",
        "askmoreofai.com",
        "assistly.com",
        "atonit.com.br",
        "atonit.digital",
        "attic.io",
        "buddymedia.com",
        "chatter.com",
        "chatter.salesforce.com",
        "clicksoftware.com",
        "cloudconnect.com",
        "cloudcraze.com",
        "cotweet.com",
        "credentialmaster.com",
        "demandware.com",
        "desk.com",
        "documentforce.com",
        "dreamforce.com"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f31193017060355040a131053616c6573666f7263652c20496e632e311730150603550403130e73616c6573666f7263652e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260923000000",
      "not_after": "20270409235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a104-109-10-129.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.salesforce.com/",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/assetlinks.json"
    ],
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=63072000; includeSubDomains; preload",
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
    "cdn": [
      "Akamai"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.digicert.com"
  },
  "elapsed_s": 65.4,
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
