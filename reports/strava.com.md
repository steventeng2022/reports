# Security Audit Report — strava.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://strava.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | strava.com |
| Test date | 2026-09-27 01:34 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
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
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS20 | Short certificate serial number (< 64 bits) | CWE-347 |
| 20 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: istio-envoy
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: istio-envoy
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
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=9a5218c79f86c05d91cd0b2e9563f5c6e8cd5572bf65e7e7686f; work-accounts-domain-verification=nLwT1cx0x4uEv9vvCACvt1Lg4luy5O; airtable-verification=de9c073c9ccf61acff9d73b8823edbef
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.godaddy.com/ -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 44 disallow path(s), e.g. /, /admin/, /api/, /stream/, /activities/*/analysis
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.56 carries PTR server-54-192-248-56.tpe53.r.cloudfront.net. for strava.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for strava.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] Short certificate serial number (< 64 bits) (`TLS20`)

- **CWE:** CWE-347
- **Detail:** Leaf certificate of strava.com carries a 63-bit serial (0x69f5447a5c10a275); serials under 64 bits make collision attacks (2008 CERTEX) feasible and are no longer recommended by the CA/B Forum.
- **Recommendation:** Request certificates with 128-bit serial numbers.

### 20. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on strava.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

## Evidence (raw response observations)

```json
{
  "domain": "strava.com",
  "dns": {
    "a": [
      "54.192.248.56",
      "54.192.248.90",
      "54.192.248.128",
      "54.192.248.55"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx3.googlemail.com (pref 50)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 40)"
    ],
    "ns": [
      "ns-610.awsdns-12.net.",
      "ns-145.awsdns-18.com.",
      "ns-1461.awsdns-54.org.",
      "ns-1806.awsdns-33.co.uk."
    ],
    "caa": [],
    "spf": [
      "adobe-idp-site-verification=9a5218c79f86c05d91cd0b2e9563f5c6e8cd5572bf65e7e7686f55a90cf1befc",
      "work-accounts-domain-verification=nLwT1cx0x4uEv9vvCACvt1Lg4luy5O",
      "airtable-verification=de9c073c9ccf61acff9d73b8823edbef",
      "loom-site-verification=b0f23be7d86c413d868b47f2d93ec03e",
      "atlassian-domain-verification=4SfbkeWjP1TP5ROrzUdI40l9E0MqiStUDoG2m4KYvKDtsBhLnniowUc7ILCsYZ1S",
      "jamf-site-verification=w9mElzcFuOBxXmCXv2bCpA",
      "apple-domain-verification=9ACAsKFrulr6AjAT",
      "zapier-domain-verification-challenge=aaed450e-ad27-40cc-90a3-8946ab1a6998",
      "google-site-verification=KKJriV53T6NWYsL-B85XmGlIGGVSQU7Iz1hA7L3lqgc",
      "decagon-domain-verification-4pmp61=bzrLxzaMsSC8YBwPLgVYm9xSC",
      "google-site-verification=8oa-S3w8xvrsbI6gFOLjiipTrm_TizA54b2WptEosBY",
      "cloudflare_dashboard_sso=9369287776c37e9ac8fb04bf9053fd26",
      "mixpanel-domain-verify=7a9d27b9-b001-4b6c-9015-6ca9d511eb0e",
      "google-site-verification=b-brkKP8oTaok4WqJS4ip220QWuatmTIa9_9-4yP0Rg",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "notion-domain-verification=5btQssUe0luq0yarLdA50PxDGvHA6JIqrSaOyQvO0fs",
      "hubspot-domain-verification=OGRkN2YzMDQtNzE4My00MGJlLWI1ODktNzM4ZmJmMDExMjEy",
      "google-site-verification=z9engXe1IAxie3KkQEmv3FU2paPe3wciOlRip5-AyA8",
      "cursor-domain-verification-xxvmxc=08C6fCgWX5w8WDgwWcYQaMI9E",
      "docker-verification=2e6711c6-5d4d-4dbf-802d-e9c0eafda287",
      "google-site-verification=w4nbPkV1Xy_Sha-bUciA4fLF1L3jNqunS7B3BZ3jmk0",
      "google-site-verification=7V-jaWtdlKU59XzrF3bZjomZygEWkYS4B1du-Tn6WTk",
      "MS=C4B6EF60D51B967591B73261035E0C54EDF75375",
      "mixpanel-domain-verify=d81ed633-675a-4e48-a5ca-26304e495168",
      "tiktok-developers-site-verification=TaDdWWlWycl7vyceILq930ykKqH5rE31",
      "anthropic-domain-verification-stddgc=YcuPCewLcCRlX44Nt6YT7iWGa",
      "docusign=76e529f9-f4ae-4745-b880-de1c9d1417f6"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email,mailto:dmarc@strava.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.strava.com",
    "issuer": "countryName=US, organizationName=GoDaddy.com, commonName=GoDaddy TLS Intermediate CA DV - R1v1",
    "notBefore": "Sep  2 20:56:39 2026 GMT",
    "notAfter": "Mar 19 20:56:39 2027 GMT",
    "san": [
      "*.strava.com",
      "strava.com"
    ],
    "days_left": 173,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.56",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: istio-envoy"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.strava.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://strava.com/"
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
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "adobe-idp-site-verification=9a5218c79f86c05d91cd0b2e9563f5c6e8cd5572bf65e7e7686f",
    "work-accounts-domain-verification=nLwT1cx0x4uEv9vvCACvt1Lg4luy5O",
    "airtable-verification=de9c073c9ccf61acff9d73b8823edbef",
    "loom-site-verification=b0f23be7d86c413d868b47f2d93ec03e",
    "atlassian-domain-verification=4SfbkeWjP1TP5ROrzUdI40l9E0MqiStUDoG2m4KYvKDtsBhLnn"
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
      "aia_ocsp": "http://ocsp.godaddy.com/",
      "serial": 7635084035597836917,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.godaddy.com/gdr1v1dv_s1-14.crl"
      ],
      "subject_dn": "3115301306035504030c0c2a2e7374726176612e636f6d",
      "issuer_dn": "310b300906035504061302555331143012060355040a130b476f44616464792e636f6d312e302c06035504031325476f446164647920544c5320496e7465726d656469617465204341204456202d2052317631",
      "not_before": "20260902205639",
      "not_after": "20270319205639"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/admin/",
      "/api/",
      "/stream/",
      "/activities/*/analysis",
      "/activities/*/embed/",
      "/activities/*/est-power-*",
      "/activities/*/flags/new",
      "/activities/*/heartrate",
      "/activities/*/laps",
      "/activities/*/matched*",
      "/activities/*/overview",
      "/activities/*/pace-*",
      "/activities/*/potential-segment*",
      "/activities/*/power-*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-54-192-248-56.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.strava.com/",
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
    "serial_bits": 63,
    "root_status": 301,
    "crl": {
      "url": "http://crl.godaddy.com/gdr1v1dv_s1-14.crl",
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
  "elapsed_s": 18.6,
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
