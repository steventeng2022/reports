# Security Audit Report — yandex.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yandex.com/ |
| Bug bounty program | Yandex |
| Listed scope domain | yandex.com |
| Test date | 2026-09-27 02:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 5, Info: 18)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
| 7 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 8 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 14 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 17 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 18 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 19 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 20 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 21 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 22 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 23 | info | HTML19 | data: URIs present in root document | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

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

### 6. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.yandex.com -> Access-Control-Allow-Origin: https://sub.yandex.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

### 7. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 8. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.yandex.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (z2qxfbzverjcc1.yandex.com and udmxbb44b1kcks.yandex.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=LUbMcUb0Zdviv4wd-A5JeHEzy5xZYZSWQQ0cxuo80l; google-site-verification=FVk3gum7zZLdkqi96ypScROFMew0wMetq1Gpu4rkzPI; facebook-domain-verification=625igbkehyfptcek6nh1hz7q4s3h4a
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but yandex.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 618 disallow path(s), e.g. /?, /403.html, /404.html, /500.html, /about.html
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of yandex.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 14. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of yandex.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 77.88.55.88 carries PTR yandex.ru. for yandex.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on yandex.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 17. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The yandex.com certificate lists an AIA OCSP responder (http://ocsp.globalsign.com/gseccovsslca2018) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 18. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on yandex.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 19. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of yandex.com references 9 distinct third-party registrable domains (e.g. yastatic.net, w3.org, ya.ru, yandex.by, yandex.kz); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 20. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of yandex.com sends a CSP but contains 5 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 21. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of yandex.com contains wildcard SAN entry(ies) *.yandex.tr, *.xn--d1acpjx3f.xn--p1ai, *.yandex.aero; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 22. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of yandex.com is http://ocsp.globalsign.com/gseccovsslca2018; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 23. [INFO] data: URIs present in root document (`HTML19`)

- **CWE:** CWE-200
- **Detail:** The root document of yandex.com references 9 data: URI payload(s); inline data resources bypass the normal fetch/CORS path and should be inventoried.
- **Recommendation:** Review inline data payloads (especially scripts/iframes) as part of the asset inventory.

## Evidence (raw response observations)

```json
{
  "domain": "yandex.com",
  "dns": {
    "a": [
      "77.88.55.88",
      "77.88.44.55",
      "5.255.255.77"
    ],
    "aaaa": [
      "2a02:6b8:a::a"
    ],
    "cname": null,
    "mx": [
      "mx.yandex.ru (pref 10)"
    ],
    "ns": [
      "ns1.yandex.net.",
      "ns2.yandex.net."
    ],
    "caa": [
      "0 issuewild \"globalsign.com\"",
      "0 issue \"globalsign.com\""
    ],
    "spf": [
      "_globalsign-domain-verification=LUbMcUb0Zdviv4wd-A5JeHEzy5xZYZSWQQ0cxuo80l",
      "google-site-verification=FVk3gum7zZLdkqi96ypScROFMew0wMetq1Gpu4rkzPI",
      "facebook-domain-verification=625igbkehyfptcek6nh1hz7q4s3h4a",
      "facebook-domain-verification=gy3xj2e9mxu0vtcdgqcznoaxoaiv63",
      "v=spf1 redirect=_spf.yandex.ru",
      "5849d1f0fc8a9e73d82dfed9f2c33931"
    ],
    "dmarc": [
      "v=DMARC1; p=none; fo=1; rua=mailto:dmarc_agg@auth.returnpath.net,mailto:dmarc-rua@yandex.ru; ruf=mailto:dmarc_afrf@auth.returnpath.net"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=RU, stateOrProvinceName=Moscow, localityName=Moscow, organizationName=YANDEX LLC, commonName=*.yandex.tr",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign ECC OV SSL CA 2018",
    "notBefore": "Jul  1 14:54:10 2026 GMT",
    "notAfter": "Dec 29 20:59:59 2026 GMT",
    "san": [
      "*.yandex.tr",
      "xn--d1acpjx3f.xn--p1ai",
      "*.xn--d1acpjx3f.xn--p1ai",
      "yandex.aero",
      "*.yandex.aero",
      "yandex.jobs",
      "*.yandex.jobs",
      "yandex.net",
      "*.yandex.net",
      "yandex.org",
      "*.yandex.org",
      "yandex.de",
      "*.yandex.de",
      "ya.ru",
      "*.ya.ru",
      "yandex.it",
      "*.yandex.it",
      "yandex.uz",
      "*.yandex.uz",
      "yandex.tm",
      "*.yandex.tm",
      "yandex.tj",
      "*.yandex.tj",
      "yandex.ru",
      "*.yandex.ru",
      "yandex.md",
      "*.yandex.md",
      "yandex.lv",
      "*.yandex.lv",
      "yandex.lt",
      "*.yandex.lt",
      "yandex.kz",
      "*.yandex.kz",
      "yandex.fr",
      "*.yandex.fr",
      "yandex.ee",
      "*.yandex.ee",
      "yandex.com.tr",
      "*.yandex.com.tr",
      "yandex.com.ge",
      "*.yandex.com.ge",
      "yandex.com.am",
      "*.yandex.com.am",
      "yandex.com",
      "*.yandex.com",
      "yandex.co.il",
      "*.yandex.co.il",
      "yandex.by",
      "*.yandex.by",
      "yandex.az",
      "*.yandex.az",
      "yandex.tr"
    ],
    "days_left": 93,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "77.88.55.88",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Yandex — fast Internet search"
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": "yandex.com",
      "samesite": "none"
    },
    {
      "domain": "yandex.com",
      "samesite": "none"
    },
    {
      "domain": "yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    },
    {
      "domain": ".yandex.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.yandex.com",
      "acao": "https://sub.yandex.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://yandex.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "_globalsign-domain-verification=LUbMcUb0Zdviv4wd-A5JeHEzy5xZYZSWQQ0cxuo80l",
    "google-site-verification=FVk3gum7zZLdkqi96ypScROFMew0wMetq1Gpu4rkzPI",
    "facebook-domain-verification=625igbkehyfptcek6nh1hz7q4s3h4a",
    "facebook-domain-verification=gy3xj2e9mxu0vtcdgqcznoaxoaiv63"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": "http://ocsp.globalsign.com/gseccovsslca2018",
      "serial": 8844451156571877789673272355,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/gseccovsslca2018.crl"
      ],
      "san": [
        "*.yandex.tr",
        "xn--d1acpjx3f.xn--p1ai",
        "*.xn--d1acpjx3f.xn--p1ai",
        "yandex.aero",
        "*.yandex.aero",
        "yandex.jobs",
        "*.yandex.jobs",
        "yandex.net",
        "*.yandex.net",
        "yandex.org",
        "*.yandex.org",
        "yandex.de",
        "*.yandex.de",
        "ya.ru",
        "*.ya.ru",
        "yandex.it",
        "*.yandex.it",
        "yandex.uz",
        "*.yandex.uz",
        "yandex.tm"
      ],
      "subject_dn": "310b3009060355040613025255310f300d060355040813064d6f73636f77310f300d060355040713064d6f73636f7731133011060355040a130a59414e444558204c4c433114301206035504030c0b2a2e79616e6465782e7472",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312630240603550403131d476c6f62616c5369676e20454343204f562053534c2043412032303138",
      "not_before": "20260701145410",
      "not_after": "20261229205959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/?",
      "/403.html",
      "/404.html",
      "/500.html",
      "/about.html",
      "/adddata",
      "/adresa-segmentator",
      "/advanced_engl.html",
      "/advertising",
      "/ads/",
      "/adfox/",
      "/an/",
      "/alice/chat/",
      "/all-supported-params",
      "/articles"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "yandex.ru."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=31536000; includeSubDomains",
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://crl.globalsign.com/gseccovsslca2018.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200
  },
  "x17": {
    "wildcard_san": [
      "*.yandex.tr",
      "*.xn--d1acpjx3f.xn--p1ai",
      "*.yandex.aero",
      "*.yandex.jobs",
      "*.yandex.net"
    ],
    "ocsp_http": "http://ocsp.globalsign.com/gseccovsslca2018",
    "data_uris": 9
  },
  "elapsed_s": 62.9,
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
