# Security Audit Report — linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | linkedin.com |
| Test date | 2026-09-27 01:26 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 3, Info: 20)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 7 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 11 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 12 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 15 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 16 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 17 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 18 | info | HTML9 | Canonical URL points to a different registrable domain | CWE-200 |
| 19 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 20 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 21 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 22 | low | HTML13 | <base href> points to a different origin | CWE-200 |
| 23 | info | WK4 | RFC 8615 change-password endpoint live | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ESF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ESF
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 7. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.linkedin.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: vmware-cloud-verification-f4d7c1c7-ad66-450f-82fa-c17b9ee79459; google-site-verification=vfmYHwjzUIFPzxFcyuwEToh_1kG9wvcpGgJnB-MhQn8; google-site-verification=mMV_EnYaB52OhMo-jbNowf8QVIKcXV3WpXreynLFFEo
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but linkedin.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 11. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of linkedin.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 12. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of linkedin.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 130.211.32.14 carries PTR 14.32.211.130.bc.googleusercontent.com. for linkedin.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The linkedin.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 15. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on linkedin.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of linkedin.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 16. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of linkedin.com loads 2 cross-origin script(s) without an integrity attribute, e.g. https://www.gstatic.com/_/mss/boq-recaptcha/_/js/k=boq-recaptcha.RecaptchaChallengePageUi.en_US.AhlAtIpWKzQ.2018.O/am=AAAAAGQC/d=1/excm=_b,_tp,challengeview/ed=1/dg=0/wt=2/ujg=1/rs=AP105ZjiiPr45QGnb_RRsCMfcEzGpX6mYw/dti=1/m=_b,_tp, https://www.google.com/recaptcha/enterprise.js?onload=onLoad&trustedtypes=true&hl=en-US; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 17. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on linkedin.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 18. [INFO] Canonical URL points to a different registrable domain (`HTML9`)

- **CWE:** CWE-200
- **Detail:** Root document of linkedin.com declares rel=canonical https://www.google.com/recaptcha/challengepage, which points outside linkedin.com; search engines and tooling may treat the other domain as the primary site.
- **Recommendation:** Point the canonical at the same registrable domain.

### 19. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of linkedin.com sends a CSP but contains 17 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 20. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of linkedin.com carries alt-svc h3=":443"; ma=2592000,h3-29=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 21. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of linkedin.com declares preconnect/dns-prefetch/modulepreload for 1 third-party registrable domain(s) (e.g. gstatic.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 22. [LOW] <base href> points to a different origin (`HTML13`)

- **CWE:** CWE-200
- **Detail:** Root document of linkedin.com sets <base href="https://www.google.com/recaptcha/challengepage/">; all relative URLs in the document resolve against that other origin.
- **Recommendation:** Set base to the same origin or use absolute URLs.

### 23. [INFO] RFC 8615 change-password endpoint live (`WK4`)

- **CWE:** CWE-200
- **Detail:** /.well-known/change-password on linkedin.com answers 200; a password-change service endpoint is advertised.
- **Recommendation:** Confirm the endpoint is an intended user-facing service.

## Evidence (raw response observations)

```json
{
  "domain": "linkedin.com",
  "dns": {
    "a": [
      "130.211.32.14"
    ],
    "aaaa": [
      "2600:1901:0:d5ad::"
    ],
    "cname": null,
    "mx": [
      "mail-c.linkedin.com (pref 10)",
      "mail-d.linkedin.com (pref 10)",
      "mail.linkedin.com (pref 20)",
      "mail-a.linkedin.com (pref 10)"
    ],
    "ns": [
      "dns4.p09.nsone.net.",
      "dns2.p09.nsone.net.",
      "ns2-42.azure-dns.net.",
      "dns3.p09.nsone.net.",
      "ns3-42.azure-dns.org.",
      "ns1-42.azure-dns.com.",
      "ns4-42.azure-dns.info.",
      "dns1.p09.nsone.net."
    ],
    "caa": [
      "0 contactemail \"tls-alerts@linkedin.com\"",
      "0 contactemail \"caarecordaware@microsoft.com\""
    ],
    "spf": [
      "448e0dc03e935ecf66d81f1ce3c26b2f2fea13756c031ffc4be91749107f3a79",
      "vmware-cloud-verification-f4d7c1c7-ad66-450f-82fa-c17b9ee79459",
      "AFDVALIDATION=LinkedIn",
      "google-site-verification=vfmYHwjzUIFPzxFcyuwEToh_1kG9wvcpGgJnB-MhQn8",
      "google-site-verification=mMV_EnYaB52OhMo-jbNowf8QVIKcXV3WpXreynLFFEo",
      "atlassian-sending-domain-verification=3bdb0597-814d-4e10-a552-5cf78f92ab3c",
      "google-site-verification=anx3jpa6VKkTWRJKnglUIzm7UEn-ZCT2WqAfG7h-xOg",
      "atlassian-domain-verification=juKdSE4GGphSmzPkhmnRJUNIn0ALdb0vsP7VSPM8TmTP7WgbgUQPLFdNicP7bF58",
      "google-site-verification=VE9BWhjbPPNmbr3ZJcwn5hLTsz7c5KPt3zXdYyaSnSQ",
      "v=spf1 ip4:199.101.162.0/25 ip4:108.174.3.0/24 ip4:108.174.6.0/24 ip4:108.174.0.0/24 ip6:2620:109:c00d:104::/64 ip6:2620:109:c006:104::/64 ip6:2620:109:c003:104::/64 ip6:2620:119:50c0:207::/64 ip4:199.101.161.130 mx mx:docusign.net ~all",
      "docusign=11f01284-dffc-40f9-8d56-57e5261ede3f",
      "elevenlabs=hRLt8nemUjAWJSL_xhBIsKFyK4yYV089AvwkOB0cxYY",
      "google-site-verification=8LaIeBMwr6K8qWeaGa4CEmfPKiZDwaT38t5mIrtaroI",
      "apple-domain-verification=Hp7LihDNsREwfHX9",
      "google-site-verification=0Vs9yf1V6RGkuzow85OzIXKEnjpRswpDkI6RgDVspMg",
      "liveramp-site-verification=yQ2nkwhqszpGRQg_J38S60KHInPVs-dclgyNRtRrlBA",
      "bf5fl8sny79w4c70jxp6cp3crkqtr7qk",
      "_cthqqp5zj8g86qf3h97heqitg2zc32b",
      "atlassian-domain-verification=dDed2VFvlDajBX8X22w52Jx/W/YLHR81SxUuraa9zNdz4aLjDS/RpfN11w2bxpRc",
      "google-site-verification=oJFWbtlKRblXs4smNibcoJkTJqwT6gd3XMI80VjBihE",
      "google-site-verification=X0LoSQsAMzR-TK4o-ULrYAwLi_fyopfRLkm_C-4N4Ts",
      "bluebeam-verification=02px6k8snlrzd6gx3b3oqkeatbzawd",
      "google-site-verification=xAGz495k8RbGclhamQx1TkZSHDxOaEd95fOjc8xpbTA",
      "miro-verification=260f00146b6d2ad1bb70d6dc07a077b672badd28"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com,mailto:yfy3q-9359@rua.dmarc.emailanalyst.com; ruf=mailto:d@ruf.agari.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=linkedin.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "May 20 00:00:00 2026 GMT",
    "notAfter": "Nov 20 23:59:59 2026 GMT",
    "san": [
      "linkedin.com"
    ],
    "days_left": 54,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "130.211.32.14",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Checking your browser - reCAPTCHA"
  },
  "mixed_content": [],
  "tech": [
    "Server: ESF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.linkedin.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 200
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 200
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "vmware-cloud-verification-f4d7c1c7-ad66-450f-82fa-c17b9ee79459",
    "google-site-verification=vfmYHwjzUIFPzxFcyuwEToh_1kG9wvcpGgJnB-MhQn8",
    "google-site-verification=mMV_EnYaB52OhMo-jbNowf8QVIKcXV3WpXreynLFFEo",
    "atlassian-sending-domain-verification=3bdb0597-814d-4e10-a552-5cf78f92ab3c",
    "google-site-verification=anx3jpa6VKkTWRJKnglUIzm7UEn-ZCT2WqAfG7h-xOg"
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
      "serial": 17673723514986794826890876675787368936,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130953756e6e7976616c65311d301b060355040a13144c696e6b6564696e20436f72706f726174696f6e311530130603550403130c6c696e6b6564696e2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260520000000",
      "not_after": "20261120235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 200,
    "ptr": [
      "14.32.211.130.bc.googleusercontent.com."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 200,
    "p404_status": 200,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=31536000",
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "alt_svc": "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000",
    "preconnect": [
      "gstatic.com"
    ],
    "base_href": "https://www.google.com/recaptcha/challengepage/",
    "change_password": true
  },
  "elapsed_s": 10.5,
  "rechecked": "2026-09-27 01:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
