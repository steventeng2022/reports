# Security Audit Report — books.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://books.google.com/ |
| Bug bounty program | Google |
| Listed scope domain | books.google.com |
| Test date | 2026-09-27 02:20 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 3, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | CK5 | Cookie scoped to parent domain (.google.com) | CWE-200 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 19 | info | HTML10 | Plaintext email addresses in the document | CWE-200 |
| 20 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 21 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 22 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: OFE/0.1
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=604800 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: OFE/0.1
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://books.google.com/?hl=en.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of books.google.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but books.google.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] Cookie scoped to parent domain (.google.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host books.google.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 178 disallow path(s), e.g. /search, /sdch, /groups, /index.html?, /?
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 142.250.196.206 carries PTR nctsaa-ac-in-f14.1e100.net. for books.google.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on books.google.com is 'OFE/0.1' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 19. [INFO] Plaintext email addresses in the document (`HTML10`)

- **CWE:** CWE-200
- **Detail:** Root document of books.google.com contains 2 plaintext email address(es) (e.g. dcarlsson@google.com, robert@broofa.com); these are harvestable by bots.
- **Recommendation:** Use a contact form or mailto obfuscation for non-critical addresses.

### 20. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of books.google.com carries alt-svc h3=":443"; ma=2592000,h3-29=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 21. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of books.google.com contains wildcard SAN entry(ies) *.google.com, *.appengine.google.com, *.bdn.dev; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 22. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of books.google.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

## Evidence (raw response observations)

```json
{
  "domain": "books.google.com",
  "dns": {
    "a": [
      "142.250.196.206"
    ],
    "aaaa": [
      "2404:6800:4012:6::200e"
    ],
    "cname": null,
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
    "subject": "commonName=*.google.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR2",
    "notBefore": "Sep 10 19:21:53 2026 GMT",
    "notAfter": "Dec  3 19:21:52 2026 GMT",
    "san": [
      "*.google.com",
      "*.appengine.google.com",
      "*.bdn.dev",
      "*.origin-test.bdn.dev",
      "*.cloud.google.com",
      "*.crowdsource.google.com",
      "*.datacompute.google.com",
      "*.google.ca",
      "*.google.cl",
      "*.google.co.in",
      "*.google.co.jp",
      "*.google.co.uk",
      "*.google.com.ar",
      "*.google.com.au",
      "*.google.com.br",
      "*.google.com.co",
      "*.google.com.mx",
      "*.google.com.tr",
      "*.google.com.vn",
      "*.google.de",
      "*.google.es",
      "*.google.fr",
      "*.google.hu",
      "*.google.it",
      "*.google.nl",
      "*.google.pl",
      "*.google.pt",
      "*.gemini.cloud.google.com",
      "*.gstatic.com",
      "*.metric.gstatic.com",
      "*.gvt1.com",
      "*.gcpcdn.gvt1.com",
      "*.gvt2.com",
      "*.gcp.gvt2.com",
      "*.url.google.com",
      "*.youtube-nocookie.com",
      "*.ytimg.com",
      "ai.android",
      "android.com",
      "*.android.com",
      "*.flash.android.com",
      "g.co",
      "*.g.co",
      "goo.gl",
      "www.goo.gl",
      "google-analytics.com",
      "*.google-analytics.com",
      "google.com",
      "googlecommerce.com",
      "*.googlecommerce.com",
      "urchin.com",
      "*.urchin.com",
      "youtu.be",
      "youtube.com",
      "*.youtube.com",
      "music.youtube.com",
      "*.music.youtube.com",
      "youtubeeducation.com",
      "*.youtubeeducation.com",
      "youtubekids.com",
      "*.youtubekids.com",
      "yt.be",
      "*.yt.be",
      "android.clients.google.com",
      "*.aistudio.google.com"
    ],
    "days_left": 67,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "142.250.196.206",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Google Books: Find, Preview, and Read Books Online."
  },
  "mixed_content": [
    "href=\"http://",
    "href=\"http://"
  ],
  "tech": [
    "Server: OFE/0.1"
  ],
  "cookies": [
    {
      "domain": ".google.com",
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
      "origin": "https://sub.books.google.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://books.google.com/?hl=en"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
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
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 91374321421071198902268481174050507237,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/wr2/oQ6nyr8F0m0.crl"
      ],
      "san": [
        "*.google.com",
        "*.appengine.google.com",
        "*.bdn.dev",
        "*.origin-test.bdn.dev",
        "*.cloud.google.com",
        "*.crowdsource.google.com",
        "*.datacompute.google.com",
        "*.google.ca",
        "*.google.cl",
        "*.google.co.in",
        "*.google.co.jp",
        "*.google.co.uk",
        "*.google.com.ar",
        "*.google.com.au",
        "*.google.com.br",
        "*.google.com.co",
        "*.google.com.mx",
        "*.google.com.tr",
        "*.google.com.vn",
        "*.google.de"
      ],
      "subject_dn": "3115301306035504030c0c2a2e676f6f676c652e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303575232",
      "not_before": "20260910192153",
      "not_after": "20261203192152"
    }
  },
  "http2": {
    "robots_disallow": [
      "/search",
      "/sdch",
      "/groups",
      "/index.html?",
      "/?",
      "/goto?",
      "/?hl=*&",
      "/?hl=*&*&gws_rd=ssl",
      "/imgres",
      "/u/",
      "/setprefs",
      "/m?",
      "/m/",
      "/wml?",
      "/wml/?"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "nctsaa-ac-in-f14.1e100.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 302,
    "p404_status": 404,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=604800",
    "crl": {
      "url": "http://c.pki.goog/wr2/oQ6nyr8F0m0.crl",
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
    "alt_svc": "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000"
  },
  "x17": {
    "wildcard_san": [
      "*.google.com",
      "*.appengine.google.com",
      "*.bdn.dev",
      "*.origin-test.bdn.dev",
      "*.cloud.google.com"
    ]
  },
  "elapsed_s": 14.1,
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
