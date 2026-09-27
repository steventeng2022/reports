# Security Audit Report — policies.google.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://policies.google.com/ |
| Bug bounty program | Google |
| Listed scope domain | policies.google.com |
| Test date | 2026-09-27 02:42 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 5, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | CK5 | Cookie scoped to parent domain (.google.com) | CWE-200 |
| 16 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 17 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 19 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 20 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 21 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 22 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 23 | info | H13 | Cross-origin isolation only partially configured | CWE-693 |
| 24 | info | HTML19 | data: URIs present in root document | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ESF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ESF
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: tiktok-developers-site-verification=JNBpjtNtdyoiPfoZ8xhXCxeprdUXFXOF
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of policies.google.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] Cookie scoped to parent domain (.google.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host policies.google.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 16. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of policies.google.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 17. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of policies.google.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 64.233.187.139 carries PTR tj-in-f139.1e100.net. for policies.google.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 19. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of policies.google.com sends a CSP but contains 4 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 20. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of policies.google.com carries alt-svc h3=":443"; ma=2592000,h3-29=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 21. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of policies.google.com declares preconnect/dns-prefetch/modulepreload for 1 third-party registrable domain(s) (e.g. gstatic.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 22. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of policies.google.com contains wildcard SAN entry(ies) *.google.com, *.appengine.google.com, *.bdn.dev; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 23. [INFO] Cross-origin isolation only partially configured (`H13`)

- **CWE:** CWE-693
- **Detail:** The root of policies.google.com sends COOP without COEP (unsafe-none); effective cross-origin isolation requires both COOP and COEP.
- **Recommendation:** Add the missing header (or remove the partial configuration).

### 24. [INFO] data: URIs present in root document (`HTML19`)

- **CWE:** CWE-200
- **Detail:** The root document of policies.google.com references 5 data: URI payload(s); inline data resources bypass the normal fetch/CORS path and should be inventoried.
- **Recommendation:** Review inline data payloads (especially scripts/iframes) as part of the asset inventory.

## Evidence (raw response observations)

```json
{
  "domain": "policies.google.com",
  "dns": {
    "a": [
      "64.233.187.139",
      "64.233.187.113",
      "64.233.187.102",
      "64.233.187.138",
      "64.233.187.101",
      "64.233.187.100"
    ],
    "aaaa": [
      "2404:6800:4008:c05::8a",
      "2404:6800:4008:c05::66",
      "2404:6800:4008:c05::65",
      "2404:6800:4008:c05::71"
    ],
    "cname": null,
    "mx": [
      "gmr-smtp-in.l.google.com (pref 5)",
      "alt2.gmr-smtp-in.l.google.com (pref 20)",
      "alt4.gmr-smtp-in.l.google.com (pref 40)",
      "alt1.gmr-smtp-in.l.google.com (pref 10)",
      "alt3.gmr-smtp-in.l.google.com (pref 30)"
    ],
    "ns": [],
    "caa": [],
    "spf": [
      "tiktok-developers-site-verification=JNBpjtNtdyoiPfoZ8xhXCxeprdUXFXOF",
      "v=spf1 redirect=_spf.google.com"
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
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE2",
    "notBefore": "Sep 10 19:22:01 2026 GMT",
    "notAfter": "Dec  3 19:22:00 2026 GMT",
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
    "ip": "64.233.187.139",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Privacy &amp; Terms – Google"
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
      "origin": "https://sub.policies.google.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://policies.google.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 404,
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
  "apex_txt": [
    "tiktok-developers-site-verification=JNBpjtNtdyoiPfoZ8xhXCxeprdUXFXOF"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 19812463921426658549740554563674554743,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we2/64OUIVzpZV4.crl"
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
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574532",
      "not_before": "20260910192201",
      "not_after": "20261203192200"
    }
  },
  "x12": {
    "status": 200,
    "ptr": [
      "tj-in-f139.1e100.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "crl": {
      "url": "http://c.pki.goog/we2/64OUIVzpZV4.crl",
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
    ]
  },
  "x17": {
    "wildcard_san": [
      "*.google.com",
      "*.appengine.google.com",
      "*.bdn.dev",
      "*.origin-test.bdn.dev",
      "*.cloud.google.com"
    ],
    "isolation_partial": "COOP without COEP",
    "data_uris": 5
  },
  "elapsed_s": 17.5,
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
