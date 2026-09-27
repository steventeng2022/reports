# Security Audit Report — podcasts.apple.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://podcasts.apple.com/ |
| Bug bounty program | Apple |
| Listed scope domain | podcasts.apple.com |
| Test date | 2026-09-27 00:29 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 2, Info: 18)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 9 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 10 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | CK5 | Cookie scoped to parent domain (.apple.com) | CWE-200 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 15 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 16 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 19 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 20 | info | SEC1 | security.txt published with a contact address | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: daiquiri/5
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=93600
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: daiquiri/5
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'geo' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 9. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'geo' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 10. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.apple.com/ocsp03-apevsrsa1g101 -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but podcasts.apple.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] Cookie scoped to parent domain (.apple.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host podcasts.apple.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 4 disallow path(s), e.g. /WebObjects/*, /api/*, /includes/*, /v1/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of podcasts.apple.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 15. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of podcasts.apple.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 16. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://podcasts.apple.com/ carries Cache-Control: max-age=60; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.209.216.33 carries PTR a23-209-216-33.deploy.static.akamaitechnologies.com. for podcasts.apple.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkzxnitt13xfed.html -> 404; error page/headers match: Akamai.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 19. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on podcasts.apple.com is 'daiquiri/5' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 20. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on podcasts.apple.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

## Evidence (raw response observations)

```json
{
  "domain": "podcasts.apple.com",
  "dns": {
    "a": [
      "23.209.216.33"
    ],
    "aaaa": [
      "2a04:4e42::774",
      "2a04:4e42:600::774",
      "2a04:4e42:400::774",
      "2a04:4e42:200::774"
    ],
    "cname": "podcasts-cdn-itunes-apple-com.v.aaplimg.com.",
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
  "cookies": [
    {
      "domain": ".apple.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.podcasts.apple.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://podcasts.apple.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 301",
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
  "cname_chain": [
    "podcasts-cdn-itunes-apple-com.v.aaplimg.com",
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
      "subject_dn": "311d301b060355040f0c1450726976617465204f7267616e697a6174696f6e31133011060b2b0601040182373c02010313025553311b3019060b2b0601040182373c0201020c0a43616c69666f726e69613111300f060355040513084330383036353932310b30090603550406130255533113301106035504080c0a43616c69666f726e69613112301006035504070c09437570657274696e6f31133011060355040a0c0a4170706c6520496e632e3119301706035504030c106974756e65732e6170706c652e636f6d",
      "issuer_dn": "310b300906035504061302555331133011060355040a130a4170706c6520496e632e312d302b060355040313244170706c65205075626c696320455620536572766572205253412043412031202d204731",
      "not_before": "20260702211531",
      "not_after": "20270107194605"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/WebObjects/*",
      "/api/*",
      "/includes/*",
      "/v1/*"
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
    "root_location": "https://podcasts.apple.com/us/new",
    "http_status": 301,
    "p404_status": 404,
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
    "security_txt": "/.well-known/security.txt",
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
  "elapsed_s": 14.1,
  "rechecked": "2026-09-27 00:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
