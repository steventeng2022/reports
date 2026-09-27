# Security Audit Report — tripadvisor.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://tripadvisor.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | tripadvisor.com |
| Test date | 2026-09-27 02:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 4, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 10 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 17 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 18 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 19 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 20 | info | CT1 | 125 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 21 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 10. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=w2N0fg0r/RRZCQ7UgNfpKKFXJH1kvCtLacvj/HzML7VZYyhEDT; openai-domain-verification=dv-5I8xhFhqZatLn3rbDbmtgpc2; bitrise-verification=b03d9c7c59423f9c-nSSshb2Ef1iv
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but tripadvisor.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 679 disallow path(s), e.g. /, /5349, /AccommodationTips, /AccountMerge, /Achievements
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.28 carries PTR server-65-9-180-28.tpe53.r.cloudfront.net. for tripadvisor.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for tripadvisor.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on tripadvisor.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 18. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of tripadvisor.com is http://ocsp.r2m04.amazontrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 19. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of tripadvisor.com discloses a 1-hop fronting chain (1.1 749a187268a37768d2b3eeb64110668c.cloudfront.net (CloudFront)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 20. [INFO] 125 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.a.tripadvisor.com, api.b.tripadvisor.com, api.content.tripadvisor.com, api.tripadvisor.com, api.w.tripadvisor.com, cdn.tripadvisor.com, certificate-requestor.ops.tripadvisor.com, docs.terra.tripadvisor.com, els-cerebro-ashburn.ops.tripadvisor.com, els-kibana1-ashburn.ops.tripadvisor.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 21. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: api.a.tripadvisor.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "tripadvisor.com",
  "dns": {
    "a": [
      "65.9.180.28",
      "65.9.180.51",
      "65.9.180.77",
      "65.9.180.34"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 10)"
    ],
    "ns": [
      "ns-218.awsdns-27.com.",
      "ns-1702.awsdns-20.co.uk.",
      "ns-584.awsdns-09.net.",
      "ns-1455.awsdns-53.org."
    ],
    "caa": [],
    "spf": [
      "atlassian-domain-verification=w2N0fg0r/RRZCQ7UgNfpKKFXJH1kvCtLacvj/HzML7VZYyhEDT7N1skt744NCyxJ",
      "openai-domain-verification=dv-5I8xhFhqZatLn3rbDbmtgpc2",
      "MS=E0371C101EE1151078A9F24A7375E7021319CF9E",
      "bitrise-verification=b03d9c7c59423f9c-nSSshb2Ef1iv",
      "pendo-domain-verification=M8PpCcCrkPq-ll2Fr1arfZA1YvI",
      "google-site-verification=u10Ue1BCmah8YviQ9Ju9IqSP-xZtlgEnBloxhP5Lhn8",
      "apple-domain-verification=jtPwxHyUkw7GVjBd",
      "pardot_211512_*=005e7416cb39efdf4ede9f02352c05fe01bf0e6c5435039550bdab7d707cae58",
      "protonmail-verification=5e35a64e327cebe41439dc21e8657f78970c051a",
      "jetbrains-domain-verification=5zlraawspitiqhi2hp4wizy31",
      "duo_sso_verification=N763Lu3Yt0ygaRnHrvqziKZ7YVtOU95w7GXyHhCljSOT7d1KVi7z2TSRd5BR4a3Q",
      "anthropic-domain-verification-pc5mq6=ebxPo8aNNofNaqlqU65hyJHjA",
      "cursor-domain-verification-bwta0g=rGWNgTQrx8pQ3A5XE0S1XxKzM",
      "sprout-social-85a564fb-ff50-11ef-b8c4-0e418c465417",
      "bnyGlxykTsBZSdNWWe3jXJ5tVU2U7gsTx6UjsZyIpHk=",
      "bugcrowd-verification=4889742e219d4b280f2d3673d147a6a9",
      "miro-verification=6ff1de40e337f458d05086183318e55305c99fe1",
      "google-site-verification=XMWC5EUo1s-TCtWPBEwzBDLUHqlmf-UcS-t7E8YRlmw",
      "astro-domain-verification=cmhtl2g8213y801lqzjo38fe8",
      "b4jddSWKFAZrS-Y8QD1o7T2nzdk",
      "docker-verification=a6e2315b-2f86-428a-84d7-52270aea1853",
      "MS=ms43904515",
      "cisco-ci-domain-verification=6de74e9c24339dc358b099e999ca47c34dd162c04f635f9810372e2000ad9f57",
      "spf2.0/pra",
      "segment-site-verification=Lv56Wm7ECxH2FrJtoG9FmQ77Co6nf93L",
      "datadome-domain-verify=LtwSY8f9UsuWkflYriVEN5xJW7jb1OGB",
      "asv=d902c0e169042b928445d5bc9a610e24",
      "v=spf1 include:_spf.tripadvisor.com include:mail.zendesk.com ~all",
      "teamviewer-sso-verification=b42c480c302645eb8ed8f32688556be4",
      "stripe-verification=A71BECF4CEF430F171A6A2382BEECE6A64B9633FC460020EB8A205A95669B679",
      "docusign=f4d14366-23f0-482a-bc08-98b15bd25db6",
      "jamf-site-verification=Ac2uXdbieW6reJXv2o4UQw",
      "docusign=4c82afdc-4187-4e03-9e78-8dbdc5ed7d0d",
      "perplexity-ai-domain-verification-2hn78f=hnjr1IgErK6Rjhxpscmyv9Ztq",
      "facebook-domain-verification=rld5ayte5pgnngj4ljg2ovn3kaeo4q",
      "_2erojipq9p68ygptyqgypy83ah2dnzz",
      "twilio-domain-verification=57fba14b7bba9c1c99652540a081cc79",
      "onetrust-domain-verification=9214adc265ab47e992a332150c6a315b",
      "_18y5y646xcsfq732og6fu2xmgabh125",
      "zapier-domain-verification-challenge=e7c8b772-89e7-420e-b76b-3a084b0bbf83",
      "_globalsign-domain-verification=GaLfs98jrznUbwIzD2n4S8pINM0PU-EyBVWkTTQvp9"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-rua@tripadvisor.com; ruf=mailto:dmarc-ruf@tripadvisor.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=tripadvisor.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 19 00:00:00 2026 GMT",
    "notAfter": "Mar  4 23:59:59 2027 GMT",
    "san": [
      "tripadvisor.com",
      "tripadvisor.jp",
      "tripadvisor.dk",
      "tripadvisor.com.eg",
      "tripadvisor.fr",
      "tripadvisor.ua",
      "tripadvisor.co.nz",
      "tripadvisor.nl",
      "tripadvisor.com.my",
      "tripadvisor.com.mx",
      "tripadvisor.rs",
      "tripadvisor.com.gr",
      "tripadvisor.de",
      "tripadvisor.pt",
      "tripadvisor.fi",
      "tripadvisor.co.hu",
      "tripadvisor.be",
      "tripadvisor.com.au",
      "tripadvisor.cz",
      "tripadvisor.com.pe",
      "tripadvisor.com.ar",
      "tripadvisor.es",
      "tripadvisor.com.tr",
      "tripadvisor.com.ph",
      "tripadvisor.com.vn",
      "tripadvisor.at",
      "tripadvisor.ch",
      "tripadvisor.in",
      "tripadvisor.co.il",
      "tripadvisor.co.kr",
      "tripadvisor.cl",
      "tripadvisor.com.hk",
      "tripadvisor.com.tw",
      "tripadvisor.co.za",
      "tripadvisor.co",
      "tripadvisor.it",
      "tripadvisor.ca",
      "tripadvisor.sk",
      "tripadvisor.com.sg",
      "tripadvisor.com.br",
      "tripadvisor.ie",
      "tripadvisor.co.uk",
      "tripadvisor.co.id",
      "tripadvisor.se"
    ],
    "days_left": 158,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.28",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.tripadvisor.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://tripadvisor.com/"
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
    "source": "certspotter",
    "count": 125,
    "notable": [
      "api.a.tripadvisor.com",
      "api.b.tripadvisor.com",
      "api.content.tripadvisor.com",
      "api.tripadvisor.com",
      "api.w.tripadvisor.com",
      "cdn.tripadvisor.com",
      "certificate-requestor.ops.tripadvisor.com",
      "docs.terra.tripadvisor.com",
      "els-cerebro-ashburn.ops.tripadvisor.com",
      "els-kibana1-ashburn.ops.tripadvisor.com",
      "els-kibana2-ashburn.ops.tripadvisor.com",
      "grfdbproxy.ops.tripadvisor.com",
      "jenkins-ashburn.ops.tripadvisor.com",
      "jenkins-master.ops.tripadvisor.com",
      "k8s-prom-ashburn.ops.tripadvisor.com"
    ],
    "sample": [
      "accounts-dev.tripadvisor.com",
      "accounts-sbx.tripadvisor.com",
      "accounts.tripadvisor.com",
      "api-bing.tripadvisor.com",
      "api.a.tripadvisor.com",
      "api.b.tripadvisor.com",
      "api.content.tripadvisor.com",
      "api.tripadvisor.com",
      "api.w.tripadvisor.com",
      "ar.tripadvisor.com",
      "assetlibrary.tripadvisor.com",
      "backup-api.tripadvisor.com",
      "brandswetravelwith.tripadvisor.com",
      "cdn.tripadvisor.com",
      "certificate-requestor.ops.tripadvisor.com",
      "cn.tripadvisor.com",
      "dev-api.content.tripadvisor.com",
      "dev-terra.tripadvisor.com",
      "docs.terra.tripadvisor.com",
      "dynamic-media-cdn.tripadvisor.com"
    ],
    "dangling": [
      "api.a.tripadvisor.com"
    ]
  },
  "apex_txt": [
    "atlassian-domain-verification=w2N0fg0r/RRZCQ7UgNfpKKFXJH1kvCtLacvj/HzML7VZYyhEDT",
    "openai-domain-verification=dv-5I8xhFhqZatLn3rbDbmtgpc2",
    "bitrise-verification=b03d9c7c59423f9c-nSSshb2Ef1iv",
    "pendo-domain-verification=M8PpCcCrkPq-ll2Fr1arfZA1YvI",
    "google-site-verification=u10Ue1BCmah8YviQ9Ju9IqSP-xZtlgEnBloxhP5Lhn8"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 4675512864041927903022622067844154809,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "san": [
        "tripadvisor.com",
        "tripadvisor.jp",
        "tripadvisor.dk",
        "tripadvisor.com.eg",
        "tripadvisor.fr",
        "tripadvisor.ua",
        "tripadvisor.co.nz",
        "tripadvisor.nl",
        "tripadvisor.com.my",
        "tripadvisor.com.mx",
        "tripadvisor.rs",
        "tripadvisor.com.gr",
        "tripadvisor.de",
        "tripadvisor.pt",
        "tripadvisor.fi",
        "tripadvisor.co.hu",
        "tripadvisor.be",
        "tripadvisor.com.au",
        "tripadvisor.cz",
        "tripadvisor.com.pe"
      ],
      "subject_dn": "311830160603550403130f7472697061647669736f722e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20260819000000",
      "not_after": "20270304235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/5349",
      "/AccommodationTips",
      "/AccountMerge",
      "/Achievements",
      "/ActionRecord",
      "/AddForumUser",
      "/AddListing",
      "/AdRequestEventLogApi",
      "/AdsManager",
      "/adsoverview",
      "/AffiliateWidgets",
      "/AirlineRegistration",
      "/AirlineTips",
      "/AirportFromGeoAjax"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-65-9-180-28.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.tripadvisor.com/",
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
    "hsts": "max-age=31536000; includeSubDomains",
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
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
    "cdn": [
      "CloudFront",
      "Fastly"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.r2m04.amazontrust.com",
    "via": "1.1 749a187268a37768d2b3eeb64110668c.cloudfront.net (CloudFront)"
  },
  "elapsed_s": 13.6,
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
