# Security Audit Report — itunes.apple.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://itunes.apple.com/ |
| Bug bounty program | Apple |
| Listed scope domain | itunes.apple.com |
| Test date | 2026-09-27 02:35 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 3, Info: 20)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 10 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 11 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | low | RD2 | HTTPS root redirects to a different domain | CWE-200 |
| 19 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 20 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 21 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 22 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 23 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: daiquiri/5
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
- **Detail:** Header reveals: daiquiri/5
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 10. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.itunes.apple.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 11. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://itunes.apple.com/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.apple.com/ocsp03-apevsrsa1g101 -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but itunes.apple.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 12 disallow path(s), e.g. /WebObjects/MZFastFinance.woa, /WebObjects/MZFinance.woa, /WebObjects/MZPersonalizer.woa, /WebObjects/MZStoreElements.woa, /station/idst.
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://itunes.apple.com/ carries Cache-Control: no-transform, max-age=0 (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.209.216.33 carries PTR a23-209-216-33.deploy.static.akamaitechnologies.com. for itunes.apple.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [LOW] HTTPS root redirects to a different domain (`RD2`)

- **CWE:** CWE-200
- **Detail:** https://itunes.apple.com/ answered 301 with Location: https://www.apple.com/itunes/ (cross-domain handoff at the entry point).
- **Recommendation:** Review the cross-domain redirect; it discloses the real entry point and can be abused in open-redirect-style flows.

### 19. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkq5dn9t4pwpr7.html -> 404; error page/headers match: Akamai.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 20. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on itunes.apple.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 21. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on itunes.apple.com is 'daiquiri/5' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 22. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on itunes.apple.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 23. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of itunes.apple.com is http://ocsp.apple.com/ocsp03-apevsrsa1g101; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "itunes.apple.com",
  "dns": {
    "a": [
      "23.209.216.33"
    ],
    "aaaa": [
      "2600:1417:76:a83::2a1",
      "2600:1417:76:a82::2a1",
      "2600:1417:76:a84::2a1",
      "2600:1417:76:a87::2a1",
      "2600:1417:76:a85::2a1"
    ],
    "cname": "itunes-cdn-itunes-apple-com.v.aaplimg.com.",
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
    "subject": "businessCategory=Private Organization, jurisdictionCountryName=US, jurisdictionStateOrProvinceName=California, serialNumber=C0806592, countryName=US, stateOrProvinceName=California, localityName=Cupertino, organizationName=Apple Inc., commonName=itunes.apple.com",
    "issuer": "countryName=US, organizationName=Apple Inc., commonName=Apple Public EV Server RSA CA 1 - G1",
    "notBefore": "Jul  2 21:15:31 2026 GMT",
    "notAfter": "Jan  7 19:46:05 2027 GMT",
    "san": [
      "apps.mzstatic.com",
      "api.music.apple.com",
      "configuration.apple.com",
      "radio-services.itunes.apple.com",
      "api.videos.apple.com",
      "is3-ssl.mzstatic.com",
      "api.podcasts.apple.com",
      "a5.mzstatic.com",
      "api.edu.apple.com",
      "accertify.mzstatic.com",
      "api.itunes.apple.com",
      "uts-api-siri.itunes.apple.com",
      "is1-ssl.mzstatic.com",
      "itc.mzstatic.com",
      "bookkeeper.itunes.apple.com",
      "itunes.apple.com",
      "upp.itunes.apple.com",
      "books.apple.com",
      "a2.mzstatic.com",
      "amp-api-edge.apps.apple.com",
      "tv.apple.com",
      "sb.music.apple.com",
      "siri-search.itunes.apple.com",
      "amp-api-edge.music.apple.com",
      "s2.mzstatic.com",
      "se.itunes.apple.com",
      "sf-api-token-service.itunes.apple.com",
      "sp.itunes.apple.com",
      "is4-ssl.mzstatic.com",
      "metrics.mzstatic.com",
      "radio.itunes.apple.com",
      "b5.mzstatic.com",
      "init.itunes.apple.com",
      "b3.mzstatic.com",
      "radio-activity.itunes.apple.com",
      "music.apple.com",
      "b1.mzstatic.com",
      "podcasts.apple.com",
      "api.apps.apple.com",
      "amp-api-search-edge.apps.apple.com",
      "is5-ssl.mzstatic.com",
      "s1.mzstatic.com",
      "api-edge.apps.apple.com",
      "tf-feedback.itunes.apple.com",
      "assets-mercury.mzstatic.com",
      "is2-ssl.mzstatic.com",
      "b2.mzstatic.com",
      "b4.mzstatic.com",
      "videos.apple.com",
      "s.mzstatic.com",
      "atve.tv.apple.com",
      "s5.mzstatic.com",
      "s3.mzstatic.com",
      "sync.itunes.apple.com",
      "a3.mzstatic.com",
      "images-mercury.mzstatic.com",
      "a4.mzstatic.com",
      "api.books.apple.com",
      "radio-quickplay.itunes.apple.com",
      "edge.itunes.apple.com",
      "pd.itunes.apple.com",
      "apps.apple.com",
      "su.itunes.apple.com",
      "search.itunes.apple.com",
      "sb.tv.apple.com",
      "s4.mzstatic.com",
      "store.mzstatic.com",
      "vocabulary.itunes.apple.com",
      "a1.mzstatic.com",
      "desktop-music-legacy.itunes.apple.com",
      "se-edge.itunes.apple.com"
    ],
    "days_left": 102,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.216.33",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: daiquiri/5"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.itunes.apple.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://itunes.apple.com/"
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
    "/.well-known/security.txt": 403,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 403,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "cname_chain": [
    "itunes-cdn-itunes-apple-com.v.aaplimg.com",
    "itunes.apple.com.edgekey.net",
    "e673.dsce9.akamaiedge.net"
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
      "aia_ocsp": "http://ocsp.apple.com/ocsp03-apevsrsa1g101",
      "serial": 125828185203218845306095832156946095994,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.apple.com/apevsrsa1g1.crl"
      ],
      "san": [
        "apps.mzstatic.com",
        "api.music.apple.com",
        "configuration.apple.com",
        "radio-services.itunes.apple.com",
        "api.videos.apple.com",
        "is3-ssl.mzstatic.com",
        "api.podcasts.apple.com",
        "a5.mzstatic.com",
        "api.edu.apple.com",
        "accertify.mzstatic.com",
        "api.itunes.apple.com",
        "uts-api-siri.itunes.apple.com",
        "is1-ssl.mzstatic.com",
        "itc.mzstatic.com",
        "bookkeeper.itunes.apple.com",
        "itunes.apple.com",
        "upp.itunes.apple.com",
        "books.apple.com",
        "a2.mzstatic.com",
        "amp-api-edge.apps.apple.com"
      ],
      "subject_dn": "311d301b060355040f0c1450726976617465204f7267616e697a6174696f6e31133011060b2b0601040182373c02010313025553311b3019060b2b0601040182373c0201020c0a43616c69666f726e69613111300f060355040513084330383036353932310b30090603550406130255533113301106035504080c0a43616c69666f726e69613112301006035504070c09437570657274696e6f31133011060355040a0c0a4170706c6520496e632e3119301706035504030c106974756e65732e6170706c652e636f6d",
      "issuer_dn": "310b300906035504061302555331133011060355040a130a4170706c6520496e632e312d302b060355040313244170706c65205075626c696320455620536572766572205253412043412031202d204731",
      "not_before": "20260702211531",
      "not_after": "20270107194605"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/WebObjects/MZFastFinance.woa",
      "/WebObjects/MZFinance.woa",
      "/WebObjects/MZPersonalizer.woa",
      "/WebObjects/MZStoreElements.woa",
      "/station/idst.",
      "/WebObjects/*",
      "/search*",
      "/*/rss/*",
      "/*/lookup?",
      "/*/album/*/*?i=*",
      "/*/tv-season/*/*?i=*",
      "/*/podcast/*/*?i=*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a23-209-216-33.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.apple.com/itunes/",
    "http_status": 302,
    "p404_status": 404,
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
    "hsts": "max-age=31536000; includeSubDomains",
    "crl": {
      "url": "http://crl.apple.com/apevsrsa1g1.crl",
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
      "Fastly"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.apple.com/ocsp03-apevsrsa1g101"
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
