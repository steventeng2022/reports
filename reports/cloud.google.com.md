# Security Audit Report — cloud.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cloud.google.com/ |
| Bug bounty program | Google |
| Listed scope domain | cloud.google.com |
| Test date | 2026-09-27 01:13 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 2, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 7 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 8 | info | CK5 | Cookie scoped to parent domain (.google.com) | CWE-200 |
| 9 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 10 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 11 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 12 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 13 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 14 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 15 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 16 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 17 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 18 | info | WK4 | RFC 8615 change-password endpoint live | CWE-200 |
| 19 | info | CT1 | 15 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 6. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: linkedin-site-verification=665646e8-9b99-454f-86a2-803db5044863; facebook-domain-verification=arpzb36y6gfzl22n4jl30bg5fsrgh0; google-site-verification=FNbpLNxt8J8XYQAudCNFnig_1bP-LAUSeAePJXlfjzU
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 7. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of cloud.google.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 8. [INFO] Cookie scoped to parent domain (.google.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host cloud.google.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 9. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of cloud.google.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 10. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of cloud.google.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 11. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 142.250.204.46 carries PTR hkg07s38-in-f14.1e100.net., lctsaa-ac-in-f14.1e100.net. for cloud.google.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 12. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on cloud.google.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of cloud.google.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 13. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on cloud.google.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 14. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of cloud.google.com references 19 distinct third-party registrable domains (e.g. x.com, google.com\, gstatic.com, facebook.com, youtube.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 15. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of cloud.google.com sends a CSP but contains 8 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 16. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of cloud.google.com carries alt-svc h3=":443"; ma=2592000,h3-29=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 17. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of cloud.google.com declares preconnect/dns-prefetch/modulepreload for 1 third-party registrable domain(s) (e.g. gstatic.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 18. [INFO] RFC 8615 change-password endpoint live (`WK4`)

- **CWE:** CWE-200
- **Detail:** /.well-known/change-password on cloud.google.com answers 200; a password-change service endpoint is advertised.
- **Recommendation:** Confirm the endpoint is an intended user-facing service.

### 19. [INFO] 15 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: console.au.cloud.google.com, console.ca.cloud.google.com, console.ch.cloud.google.com, console.eu.cloud.google.com, console.il.cloud.google.com, console.in.cloud.google.com, console.it.cloud.google.com, console.jp.cloud.google.com, console.sa.cloud.google.com, console.uk.cloud.google.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "cloud.google.com",
  "dns": {
    "a": [
      "142.250.204.46"
    ],
    "aaaa": [
      "2404:6800:4012:9::200e"
    ],
    "cname": null,
    "mx": [],
    "ns": [],
    "caa": [],
    "spf": [
      "linkedin-site-verification=665646e8-9b99-454f-86a2-803db5044863",
      "facebook-domain-verification=arpzb36y6gfzl22n4jl30bg5fsrgh0",
      "google-site-verification=FNbpLNxt8J8XYQAudCNFnig_1bP-LAUSeAePJXlfjzU",
      "google-site-verification=6nz-JOcA8VP-mmx29RInf7-g6CTloBX9wpmWHlVSMsw",
      "google-site-verification=jaH5RlwfdutdrKEaZY5nEbcReUEp9rlTOJIuMqh-SV4",
      "linkedin-site-verification=d232e0a9-aa43-41a4-8fa4-243021df793a"
    ],
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
    "ip": "142.250.204.46",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "AI and Cloud Computing Services | Google Cloud"
  },
  "mixed_content": [],
  "tech": [
    "Server: ESF"
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
      "origin": "https://sub.cloud.google.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://cloud.google.com/"
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
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 15,
    "notable": [
      "console.au.cloud.google.com",
      "console.ca.cloud.google.com",
      "console.ch.cloud.google.com",
      "console.eu.cloud.google.com",
      "console.il.cloud.google.com",
      "console.in.cloud.google.com",
      "console.it.cloud.google.com",
      "console.jp.cloud.google.com",
      "console.sa.cloud.google.com",
      "console.uk.cloud.google.com",
      "console.us.cloud.google.com",
      "datastudio.eu.cloud.google.com",
      "datastudio.us.cloud.google.com",
      "lookerstudio.eu.cloud.google.com",
      "lookerstudio.us.cloud.google.com"
    ],
    "sample": [
      "console.au.cloud.google.com",
      "console.ca.cloud.google.com",
      "console.ch.cloud.google.com",
      "console.eu.cloud.google.com",
      "console.il.cloud.google.com",
      "console.in.cloud.google.com",
      "console.it.cloud.google.com",
      "console.jp.cloud.google.com",
      "console.sa.cloud.google.com",
      "console.uk.cloud.google.com",
      "console.us.cloud.google.com",
      "datastudio.eu.cloud.google.com",
      "datastudio.us.cloud.google.com",
      "lookerstudio.eu.cloud.google.com",
      "lookerstudio.us.cloud.google.com"
    ]
  },
  "apex_txt": [
    "linkedin-site-verification=665646e8-9b99-454f-86a2-803db5044863",
    "facebook-domain-verification=arpzb36y6gfzl22n4jl30bg5fsrgh0",
    "google-site-verification=FNbpLNxt8J8XYQAudCNFnig_1bP-LAUSeAePJXlfjzU",
    "google-site-verification=6nz-JOcA8VP-mmx29RInf7-g6CTloBX9wpmWHlVSMsw",
    "google-site-verification=jaH5RlwfdutdrKEaZY5nEbcReUEp9rlTOJIuMqh-SV4"
  ],
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
      "subject_dn": "3115301306035504030c0c2a2e676f6f676c652e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303575232",
      "not_before": "20260910192153",
      "not_after": "20261203192152"
    }
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 200,
    "ptr": [
      "hkg07s38-in-f14.1e100.net.",
      "lctsaa-ac-in-f14.1e100.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 200,
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
    "alt_svc": "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000",
    "preconnect": [
      "gstatic.com"
    ],
    "change_password": true
  },
  "elapsed_s": 10.4,
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
