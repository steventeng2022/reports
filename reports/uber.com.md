# Security Audit Report — uber.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://uber.com/ |
| Bug bounty program | Uber |
| Listed scope domain | uber.com |
| Test date | 2026-09-27 02:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 1, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 14 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 15 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 16 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 17 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ufe
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ufe
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: postman-domain-verification=4c640467e16a94ba218b31f435eb42e0749d16ab4168939f9ad5; google-site-verification=bywbMPdGdGaSev-nAuHwbdYjZziw9oPeGkOgBD5UyK0; google-site-verification=9kwu-dlf_JSf0XtaHK2xK-Cowpra8TnHbfTRCa7NBk0
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for uber.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 14. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of uber.com carries alt-svc h3=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 15. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of uber.com contains wildcard SAN entry(ies) *.uber.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 16. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of uber.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 17. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of uber.com discloses a 1-hop fronting chain (1.1 google); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

## Evidence (raw response observations)

```json
{
  "domain": "uber.com",
  "dns": {
    "a": [
      "104.36.194.17"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 2)"
    ],
    "ns": [
      "edns126.ultradns.com.",
      "edns126.ultradns.org.",
      "edns126.ultradns.net.",
      "edns126.ultradns.biz."
    ],
    "caa": [],
    "spf": [
      "postman-domain-verification=4c640467e16a94ba218b31f435eb42e0749d16ab4168939f9ad5eb4ec3abb91cd63ca90ef5ccd3e4a8f4049444c3a267225ffde0ea6a9c8d84bb6e904034a1cc",
      "google-site-verification=bywbMPdGdGaSev-nAuHwbdYjZziw9oPeGkOgBD5UyK0",
      "mixpanel-domain-verify=a35ee3f7-3848-4a0b-822e-d429b507c0c6",
      "c9s6q2+D+iTzxyax7z2ol/gbj0Rqq8Loojleaq22ZDM=",
      "google-site-verification=9kwu-dlf_JSf0XtaHK2xK-Cowpra8TnHbfTRCa7NBk0",
      "docusign=635f0402-4f58-42de-8e07-e1da6d8a971a",
      "docker-verification=e121526a-c4bd-4829-8f6b-c4a3c93f0029",
      "beautifulai-site-verification=ed0fad99-1b20-4963-ab5b-538f0f915117",
      "paloaltonetworks-site-verification=f567a8ba5a35da704fb1e540c1e50bbaa33bc2ea6b87193c22e1c9ae29348b2a",
      "facebook-domain-verification=fgnbsxqefhg2pzugzl4vcw82ylgagg",
      "atlassian-domain-verification=M5S2mTVz1nn58QsIgP0q4BLRplQvKva5IHHG5usoAYecrD00FTI5zR2tzAmNnI9L",
      "duo_sso_verification=EArnP8qJQk9QUv3i30tGmhVOfsuivQxEgBlNLIF8EaD3ZimeyV2Iq5rBJQHWcaUMl",
      "ca3-ffffa27c6ab6493ba5e2ffd4f8961467",
      "duo_sso_verification=efpKKW3WtEX7Ln6CBDAQyyNA5mwOU0KxFopDN2LtcawWUcGa6BByYIq5LG69lDrq",
      "stripe-verification=79f7b9921824c7fd1cd4ffc20fc10f662a5322317c8290f124b4e18d9ebd19e0",
      "google-site-verification=yHvJ7x6qUkjrzRfaPzSO5Iu42eP70uSS0Q88xPFBbSU",
      "apple-domain-verification=NGLGgklojeSRTo9T",
      "AD5-G1R-7NJ",
      "docusign=ce93a9f0-d430-4abb-aee8-ec66524c1f12",
      "atlassian-sending-domain-verification=0302bdf3-f835-4464-979d-7beeda0dbe97",
      "uber-site-verification=56157b0f-0f5f-4bdc-8a64-9c313ac173a5",
      "omnissa-connect-verification-da151bda-e79c-445f-9099-1fead7f31add",
      "MS=607A6B094E5395250B2F88D76D42FFB6DC2C18A4",
      "_26a8qlr3df4hbl6zve94e918z0g5wud",
      "workplace-domain-verification=HhUs1CkDiWsL4Nlmkdb6IOVjrebKb1",
      "hpe-greenlake-domain-verification=6553304837784b7232736d71514737737353622d6854354e343534554c71754f",
      "mandrill_verify.UYz1FLL51N9Ky3RCgCUZGQ",
      "notion-domain-verification=ReKaEX54F5cGF2V3IKgyilPZF3TjQ34Iua63ng0LHDC",
      "mandrill_verify.5Qnmy5yihDZ4mJwXJ0VP7w",
      "Dynatrace-site-verification=95915cac-be11-4e1a-81b7-9580122d59d1__vrv8sf7b41uebre15lgg3c5tko",
      "tiktok-developers-site-verification=cCZKENHfoFc48Ks8x4K7IMa9NCyD1ggk",
      "dtm-domain-verification=EtPupN9aHsJIAtWeUzmu_aAa6o5BQsvO73iDfQIKkx4",
      "atlassian-domain-verification=MMotF76tU47LiNcsEf06+lzKmWly4PgbYpYZqHy3a9YdTdY4S43ay72YkkxTmzff",
      "v=spf1 include:uber.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mailgun.org ~all",
      "openai-domain-verification=dv-wtb3VIyo0DtnGsiQN4DnZ4c7",
      "apple-domain-verification=Da2R4Md5eAUVUg038WJnE-_ifFtCwYYc_Dlmx3EaPsU",
      "lovable_verification=workspace_01jz0y1v0ff9cv8hsxkbvawqhx",
      "crz6wwryflvvfk4kvk5lqfk78p02dc7m",
      "f621e431-a485-4094-8587-2f76f441ccab",
      "autodesk-domain-verification=wa1khlrPnOY-93pE5_nH",
      "SFMC-4eGhjXSll4RESL8vyX0CBVbTfffzejZShsyAXBrT",
      "google-site-verification=p21addAHCLTiBqVhN6P3leSJNO2ob8edJtQbICdXCj8"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Uber Technologies, Inc., commonName=*.uber.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Feb 15 00:00:00 2026 GMT",
    "notAfter": "Feb 16 23:59:59 2027 GMT",
    "san": [
      "*.uber.com",
      "uber.com"
    ],
    "days_left": 142,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.36.194.17",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ufe"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.uber.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://uber.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 429",
    "/url?url=https://evil-auditor.example/x -> 429"
  ],
  "paths": {
    "/robots.txt": 429,
    "/sitemap.xml": 429,
    "/.well-known/security.txt": 429,
    "/security.txt": 429,
    "/.git/HEAD": 429,
    "/.git/config": 429,
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 429,
    "/phpmyadmin/index.php": 429,
    "/server-status": 429,
    "/api/": 429
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "postman-domain-verification=4c640467e16a94ba218b31f435eb42e0749d16ab4168939f9ad5",
    "google-site-verification=bywbMPdGdGaSev-nAuHwbdYjZziw9oPeGkOgBD5UyK0",
    "google-site-verification=9kwu-dlf_JSf0XtaHK2xK-Cowpra8TnHbfTRCa7NBk0",
    "docker-verification=e121526a-c4bd-4829-8f6b-c4a3c93f0029",
    "beautifulai-site-verification=ed0fad99-1b20-4963-ab5b-538f0f915117"
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
      "serial": 5974400139839356468336461313998801502,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "*.uber.com",
        "uber.com"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f3120301e060355040a13175562657220546563686e6f6c6f676965732c20496e632e3113301106035504030c0a2a2e756265722e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260215000000",
      "not_after": "20270216235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 429
  },
  "x13": {
    "root_status": 429,
    "http_status": 301,
    "p404_status": 429,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 429,
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 429
  },
  "x16": {
    "root_status": 429,
    "alt_svc": "h3=\":443\"; ma=2592000"
  },
  "x17": {
    "wildcard_san": [
      "*.uber.com"
    ],
    "ocsp_http": "http://ocsp.digicert.com",
    "via": "1.1 google"
  },
  "elapsed_s": 17.2,
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
