# Security Audit Report — surveymonkey.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://surveymonkey.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | surveymonkey.com |
| Test date | 2026-09-27 01:35 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 6, Info: 18)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 20 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 21 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 22 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 23 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 24 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): us. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (ga39uf0h2nic6s.surveymonkey.com and 96eupfx4qb5vhx.surveymonkey.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=257235a8b871a199b2d89ab4f7cdaec03a65d1bf7ac30838dece; lovable_verification=CsnCfnhpmMIm2YolPLFw; atlassian-domain-verification=keQyzOto0ziFKZDVbwTZ2DhKevhwLaTNteFi1PpPs31I0CQ4GB
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 21 disallow path(s), e.g. /billing/confirmed, /billing/invoice*, /cc/, /content-svc/, /create/survey/preview*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 20. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.3 carries PTR server-65-9-180-3.tpe53.r.cloudfront.net. for surveymonkey.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 21. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for surveymonkey.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 22. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on surveymonkey.com lists 18 <loc> URL(s) across 19 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 23. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of surveymonkey.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 24. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on surveymonkey.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

## Evidence (raw response observations)

```json
{
  "domain": "surveymonkey.com",
  "dns": {
    "a": [
      "65.9.180.3",
      "65.9.180.53",
      "65.9.180.5",
      "65.9.180.59"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-1.mimecast.com (pref 10)",
      "us-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-344.awsdns-43.com.",
      "ns-1380.awsdns-44.org.",
      "ns-588.awsdns-09.net.",
      "ns-1757.awsdns-27.co.uk."
    ],
    "caa": [],
    "spf": [
      "adobe-idp-site-verification=257235a8b871a199b2d89ab4f7cdaec03a65d1bf7ac30838dececcacace5a86c",
      "lovable_verification=CsnCfnhpmMIm2YolPLFw",
      "atlassian-domain-verification=keQyzOto0ziFKZDVbwTZ2DhKevhwLaTNteFi1PpPs31I0CQ4GBiYXNZVhfxEhJv5",
      "atlassian-domain-verification=tXdvJPw4WMjcNH3/0im4gOSMKwX5hyvl1CIiMtoHaTqygGKWQmk315B62OOR0pYe",
      "google-site-verification=2ccit_qZjaKZqS5Ce8UFhP5hVYJDQXXOSup5UtUWZPo",
      "ps-cd-verification=24840ced-b149-4e15-8b6c-04b567ba36da",
      "openai-domain-verification=dv-Rizz1TAurN3w0Gk3aKfiY4U3",
      "docusign=37225db5-de2e-4e7a-be46-db11ef071be9",
      "cursor-domain-verification-6181me=rebW4WaJ5ylTKff9K0qedvm00",
      "onetrust-domain-verification=749bac94de654f24be6f1186b41d64d5",
      "anthropic-domain-verification-b77rgg=i8sv1gogitHA9QiiiBEdIE2q2",
      "stripe-verification=3BC4A50A1E91CF90D3A2954A08BBF11F16272C3BB3576499B69A54AA5A2EB9F1",
      "jvMLQ8xH8X38HutWDQXyDJP7T-iqxBoYAg1AYT0omb",
      "rOX6b5VqFrkPW2GtNMoaCyVEhwU",
      "google-site-verification=bS37nCLe4WX0alwAbP2aaEs3hgNXpocNevsjIyjJoX8",
      "asv=37950f1917e5f9e7e48b305f9e529116",
      "gc-ai-domain-verification-8m6kgf=E1mwfXukrQWqurSC6BwoYbmNu",
      "google-site-verification=qa36tpLOjyqVlObx-4lr7c-bQy2eL3AmktntNwMubnk",
      "google-site-verification=E8ZYHCDCcYtOkFiZMiBjfE3ml9AmqWzOpnd_MCOFYRM",
      "globalsign-domain-verification=273eFvKCuCXR3P_oKS85yffiPwBPz0qc1fEV1-x8Aq",
      "_knfbojommw8fgbvijgndlnl58gxdcs9",
      "jamf-site-verification=pEif9hbPcODSQUOKmu0Szw",
      "dpq1d680yv30b.cloudfront.net",
      "smartsheet-site-validation=CmW6YpxpRVTHe6aNhQxtwQmYpyT9koJf",
      "apple-domain-verification=KMruPJeKeD2jHgiK",
      "docker-verification=b29c9172-8a00-44e6-9ea4-5d4de0569f58",
      "facebook-domain-verification=asjlbqcsmgsjco17qidfpfi82a9n7f",
      "1password-site-verification=44TOWBB3QJBB5N4OLOAOZO3IFQ",
      "google-site-verification=sEtassJLvphOixgHm2AhnGmM2DkWMHjIaC-vB17aitY",
      "nlsy424z3ktz0097zg4cw6hk44chc551",
      "v=spf1 include:us._netblocks.mimecast.com include:surveymonkey.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "OSSRH-89589",
      "miro-verification=81a06891162a7afb6cb31cdeb0c608b35ce224db",
      "MS=ms60646135"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email,mailto:dmarc_agg@auth.returnpath.net,mailto:mailadmin@surveymonkey.com; ruf=mailto:dmarc_afrf@auth.returnpath.net,mailto:mailadmin@surveymonkey.com; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=surveymonkey.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Oct 28 00:00:00 2025 GMT",
    "notAfter": "Nov 26 23:59:59 2026 GMT",
    "san": [
      "surveymonkey.com",
      "ca.research.net",
      "*.surveymonkey.net",
      "*.surveymonkey.ca",
      "surveymonkey.fr",
      "surveymonkey.de",
      "eu.surveymonkey.net",
      "*.research.net",
      "smassets.net",
      "*.eu.surveymonkey.net",
      "surveymonkey.ca",
      "*.surveymonkey.fr",
      "*.smassets.net",
      "*.feedbackeconomy.com",
      "*.surveymonkey.de",
      "curiosity.central.surveymonkey.com",
      "surveymonkey.co.uk",
      "*.surveymonkey.nl",
      "*.surveymonkey.com",
      "research.net",
      "eu.surveymonkey.com",
      "feedbackeconomy.com",
      "eu.research.net",
      "surveymonkey.net",
      "*.surveymonkey.eu",
      "surveymonkey.nl",
      "*.eu.surveymonkey.com",
      "*.ca.research.net",
      "*.surveymonkey.co.uk",
      "surveymonkey.eu",
      "*.eu.research.net"
    ],
    "days_left": 60,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.3",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.surveymonkey.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://surveymonkey.com/"
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
    "/.env": 403,
    "/.htaccess": 301,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "adobe-idp-site-verification=257235a8b871a199b2d89ab4f7cdaec03a65d1bf7ac30838dece",
    "lovable_verification=CsnCfnhpmMIm2YolPLFw",
    "atlassian-domain-verification=keQyzOto0ziFKZDVbwTZ2DhKevhwLaTNteFi1PpPs31I0CQ4GB",
    "atlassian-domain-verification=tXdvJPw4WMjcNH3/0im4gOSMKwX5hyvl1CIiMtoHaTqygGKWQm",
    "google-site-verification=2ccit_qZjaKZqS5Ce8UFhP5hVYJDQXXOSup5UtUWZPo"
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
      "aia_ocsp": "http://ocsp.r2m01.amazontrust.com",
      "serial": 10056425596563615633247152915823344216,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "subject_dn": "31193017060355040313107375727665796d6f6e6b65792e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20251028000000",
      "not_after": "20261126235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/billing/confirmed",
      "/billing/invoice*",
      "/cc/",
      "/content-svc/",
      "/create/survey/preview*",
      "/login/",
      "/mp/lp/",
      "/panelweb*",
      "/r/instant/response*",
      "/sign-up/",
      "/tr/v1/",
      "/user/",
      "/user/sign-up/sso-redirect",
      "/*?usecase=",
      "/*?query="
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-65-9-180-3.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.surveymonkey.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "sitemap": {
      "urls": 18,
      "indexes": 19
    },
    "crl": {
      "url": "http://crl.r2m01.amazontrust.com/r2m01.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "alt_svc": "h3=\":443\"; ma=86400",
    "cdn": [
      "CloudFront",
      "Fastly"
    ]
  },
  "elapsed_s": 13.5,
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
