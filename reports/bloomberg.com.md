# Security Audit Report — bloomberg.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bloomberg.com/ |
| Bug bounty program | Bloomberg |
| Listed scope domain | bloomberg.com |
| Test date | 2026-09-27 02:20 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 2, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 15 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 16 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 17 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 18 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.bloomberg.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: airtable-verification=15d4376d6d99cc906abbcb295b4245da; apple-domain-verification=9cs9hMRccEtbVb8h; openai-domain-verification=dv-XaK3IjuwWpMmfss9VYKwn0eY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but bloomberg.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 130 disallow path(s), e.g. /polska, /account/*, /tosv*.html, /search, /company/search/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 15.197.146.156 carries PTR aa2f66099ca87b6fe.awsglobalaccelerator.com. for bloomberg.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The bloomberg.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 15. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on bloomberg.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of bloomberg.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 16. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on bloomberg.com is 'awselb/2.0' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 17. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of bloomberg.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 18. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of bloomberg.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

## Evidence (raw response observations)

```json
{
  "domain": "bloomberg.com",
  "dns": {
    "a": [
      "15.197.146.156",
      "3.33.146.110"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mgcnj2.bloomberg.com (pref 0)",
      "mgcny1.bloomberg.com (pref 0)",
      "mgcny2.bloomberg.com (pref 0)",
      "mgcnj1.bloomberg.com (pref 0)"
    ],
    "ns": [
      "dns3.p01.nsone.net.",
      "dns4.p01.nsone.net.",
      "pdns1.ultradns.net.",
      "pdns3.ultradns.org.",
      "dns1.p01.nsone.net.",
      "dns2.p01.nsone.net.",
      "pdns5.ultradns.info."
    ],
    "caa": [
      "0 issue \"amazon.com\"",
      "0 issue \"digicert.com\"",
      "0 issuewild \"digicert.com\"",
      "0 iodef \"mailto:reportvuln@bloomberg.net\""
    ],
    "spf": [
      "MS=ms33692690",
      "airtable-verification=15d4376d6d99cc906abbcb295b4245da",
      "2smsverify=08qXd7f0aUa5IPq0N4ETgQ",
      "v=spf1 ip4:69.184.0.0/13 ip4:199.172.169.0/24 ip4:208.22.56.0/24 ip4:69.191.241.124 -all",
      "F2QdzLTE6LTOyOQ7pQzoSY2pnwVM5pnfiqY3zOoYvS3LoVmIUr0J3op5vQI8Tg8VQwt24UK8v7oFWfbrCBWYYw==",
      "apple-domain-verification=9cs9hMRccEtbVb8h",
      "openai-domain-verification=dv-XaK3IjuwWpMmfss9VYKwn0eY",
      "ZOOM_verify_rl-mcFScS8W6864E30mlZg",
      "extensis-domain-verification=707df5b4-0868-499f-af75-51718e082698",
      "MS=ms99943004",
      "jamf-site-verification=VJNRhgJ90SmyugkIPAdfCQ",
      "parallels-domain-verification=47460854911b478da11221dc20e8cc0340a92adf1e6b4ff08a5e941f5379c267",
      "Ymxvb21iZXJn",
      "ZOOM_verify_8UDWCiGoiAVgGEuiZNG9Ld",
      "lutron-domain-verification-p8wzsk=PQcs5tfle6vYve4ulSshxyMYi",
      "cursor-domain-verification-asb77c=D43c1zjGqO3rTemQvZ121NSfi",
      "google-site-verification=ClT3QBQ-Rd4b3AAq2gmQ-u_94EliZRmC2e-Kb4t9zEo",
      "google-site-verification=CI2IKDBbk_gcKk_9CFFUrF-ZLZToKXQ7SAJ96fjqZ_I",
      "QnH3utpbwmcXnxwnErM2by/pp37P7fYtF9si0rMmb9FgwB98zU8UAzdl1GbyQMdyNFLKobFRdX6FfLlH/LG+og==",
      "google-site-verification=vH_zs-JrwvXxkyuUqmeN9t3iMYZqyt1-BJUsoyN3ca8",
      "google-gws-recovery-domain-verification=72311760",
      "atlassian-domain-verification=gK9LJEftkavNAe/keDgXDWOhGwUV02GQTz9BbfKLplkTTtpciOH5eL1W6u7BRfVR",
      "OSSRH-64276"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; adkim=r; aspf=r; ruf=mailto:dmarc-ruf@dmarc-bloomberg.com; fo=1; rua=mailto:dmarc-rua@dmarc-bloomberg.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Bloomberg LP, commonName=wmkt1.cirrus.bloomberg.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul 23 00:00:00 2026 GMT",
    "notAfter": "Jan 29 23:59:59 2027 GMT",
    "san": [
      "wmkt1.cirrus.bloomberg.com",
      "about.bloomberg.com",
      "about.bloomberginstitute.com",
      "assets.bbhub.io",
      "b20-carbon-excellence.org",
      "batscore.com",
      "bbhub.io",
      "bbthat.com",
      "beta-ee.bloomberg.com",
      "bgov200.com",
      "blog.bloomberg.com",
      "blomberggovernment.com",
      "bloom.bg",
      "bloomberg.cn",
      "bloomberg.co.jp",
      "bloomberg.co.kr",
      "bloomberg.co.uk",
      "bloomberg.com",
      "bloomberg.com.br",
      "bloomberg.com.mx",
      "bloomberg.com.tr",
      "bloomberg.de",
      "bloomberg.fr",
      "bloomberg.in",
      "bloomberg.it",
      "bloomberg.net",
      "bloomberg.tv",
      "bloomberg401k.com",
      "bloombergaffiliate.com",
      "bloombergapa.net",
      "bloombergapae.net",
      "bloombergapps.com",
      "bloombergarcade.co.uk",
      "bloombergarcade.com",
      "bloombergarm.net",
      "bloombergbeta.com",
      "bloombergbna.com",
      "bloombergbrief.com",
      "bloombergbriefs.com",
      "bloombergbtbs.com",
      "bloombergbtbs.net",
      "bloombergbtbs.sg",
      "bloombergbtbsg.com",
      "bloombergbtbsg.net",
      "bloombergbtbsg.sg",
      "bloombergbusiness.com",
      "bloombergcareer.com",
      "bloombergchina.com",
      "bloombergcms.com",
      "bloombergcompany.com",
      "bloombergcontentservice.com"
    ],
    "days_left": 124,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "15.197.146.156",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.bloomberg.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bloomberg.com:443/"
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
    "airtable-verification=15d4376d6d99cc906abbcb295b4245da",
    "apple-domain-verification=9cs9hMRccEtbVb8h",
    "openai-domain-verification=dv-XaK3IjuwWpMmfss9VYKwn0eY",
    "extensis-domain-verification=707df5b4-0868-499f-af75-51718e082698",
    "jamf-site-verification=VJNRhgJ90SmyugkIPAdfCQ"
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
      "serial": 4176607975525079089845331021555329356,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "wmkt1.cirrus.bloomberg.com",
        "about.bloomberg.com",
        "about.bloomberginstitute.com",
        "assets.bbhub.io",
        "b20-carbon-excellence.org",
        "batscore.com",
        "bbhub.io",
        "bbthat.com",
        "beta-ee.bloomberg.com",
        "bgov200.com",
        "blog.bloomberg.com",
        "blomberggovernment.com",
        "bloom.bg",
        "bloomberg.cn",
        "bloomberg.co.jp",
        "bloomberg.co.kr",
        "bloomberg.co.uk",
        "bloomberg.com",
        "bloomberg.com.br",
        "bloomberg.com.mx"
      ],
      "subject_dn": "310b30090603550406130255533111300f060355040813084e657720596f726b3111300f060355040713084e657720596f726b31153013060355040a130c426c6f6f6d62657267204c50312330210603550403131a776d6b74312e6369727275732e626c6f6f6d626572672e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260723000000",
      "not_after": "20270129235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/polska",
      "/account/*",
      "/tosv*.html",
      "/search",
      "/company/search/",
      "/professional/search/",
      "/impact/search/",
      "/ux/search/",
      "/wnwi/search/",
      "/gei/search/",
      "/impact/search/",
      "/netzeropathfinders/search/",
      "/notices/search/",
      "/distribution/search/",
      "/ukinnovators/search/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "aa2f66099ca87b6fe.awsglobalaccelerator.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.bloomberg.com/",
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
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {
    "ocsp_http": "http://ocsp.digicert.com"
  },
  "elapsed_s": 31.7,
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
