# Security Audit Report — business.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://business.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | business.linkedin.com |
| Test date | 2026-09-27 01:12 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **27** (High: 0, Medium: 0, Low: 3, Info: 24)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | DNS4 | Deep CNAME chain (>4 hops) | CWE-345 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | CK5 | Cookie scoped to parent domain (.linkedin.com) | CWE-200 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 16 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 17 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 18 | info | RD3 | Plain-HTTP root sets cookies without redirecting to HTTPS | CWE-319 |
| 19 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 20 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 21 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 22 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 23 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 24 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 25 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 26 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 27 | info | CT1 | 2 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.41:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.41:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] Deep CNAME chain (>4 hops) (`DNS4`)

- **CWE:** CWE-345
- **Detail:** CNAME chain depth 5 for business.linkedin.com.
- **Recommendation:** Shorten the CNAME chain.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but business.linkedin.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] Cookie scoped to parent domain (.linkedin.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host business.linkedin.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 15 disallow path(s), e.g. /content/, /*site-resources/, /*site-forms/, /*3qa, /*3qb
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of business.linkedin.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 16. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of business.linkedin.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 17. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on business.linkedin.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 18. [INFO] Plain-HTTP root sets cookies without redirecting to HTTPS (`RD3`)

- **CWE:** CWE-319
- **Detail:** http://business.linkedin.com/ answered 200 (no 301/308 to HTTPS) and set cookie(s) bcookie, __cf_bm over plaintext.
- **Recommendation:** Redirect plain HTTP to HTTPS and/or add the Secure attribute to cookies.

### 19. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkpyd1ylmhby2g.html -> 404; error page/headers match: Cloudflare.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 20. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on business.linkedin.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of business.linkedin.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 21. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of business.linkedin.com loads 7 cross-origin script(s) without an integrity attribute, e.g. https://content.linkedin.com/lem/static/etc.clientlibs/linkedin-experience-manager/clientlibs/clientlib-dependencies.ACSHASHd41d8cd98f00b204e9800998ecf8427e.js, https://content.linkedin.com/lem/static/etc.clientlibs/core/wcm/components/commons/datalayer/v2/clientlibs/core.wcm.components.commons.datalayer.v2.ACSHASHf55ff0cd9701de57febc6fc62640c8f0.js, https://content.linkedin.com/lem/static/etc.clientlibs/core/wcm/components/commons/datalayer/acdl/core.wcm.components.commons.datalayer.acdl.ACSHASH2587a1377e5bcf74cb428aadb430d51f.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 22. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on business.linkedin.com lists 8 <loc> URL(s) across 9 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 23. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of business.linkedin.com references 6 distinct third-party registrable domains (e.g. adobeaemcloud.com, schema.org, w3.org, linkedin-ei.com, youtube.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 24. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of business.linkedin.com sends a CSP but contains 2 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 25. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of business.linkedin.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 26. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on business.linkedin.com identify the edge as CloudFront; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 27. [INFO] 2 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "business.linkedin.com",
  "dns": {
    "a": [
      "104.18.41.41",
      "172.64.146.215"
    ],
    "aaaa": [
      "2a06:98c1:310b::ac40:92d7",
      "2a06:98c1:3109::6812:2929"
    ],
    "cname": "microsites-cn.linkedin.com.",
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
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=afd.microsites.linkedin.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Aug 22 00:00:00 2026 GMT",
    "notAfter": "Feb 22 23:59:59 2027 GMT",
    "san": [
      "afd.microsites.linkedin.com",
      "engineering.linkedin.com",
      "addtoprofile.linkedin.com",
      "lifg.linkedin.com",
      "rum15.perf.linkedin.com",
      "about.linkedin.com",
      "blog.linkedin.com",
      "brand.linkedin.com",
      "bringinyourparents.linkedin.com",
      "business.linkedin.com",
      "careers.linkedin.com",
      "cba.linkedin.com",
      "certification.linkedin.com",
      "cities.linkedin.com",
      "cms.linkedin.com",
      "commsconnect.linkedin.com",
      "conscious.linkedin.com",
      "contacts.linkedin.com",
      "customersuccess.linkedin.com",
      "data.linkedin.com",
      "design.linkedin.com",
      "developer.linkedin.com",
      "economicgraph.linkedin.com",
      "economicgraphchallenge.linkedin.com",
      "emea.marketing.linkedin.com",
      "financeconnect.linkedin.com",
      "gsk.linkedin.com",
      "hackday.linkedin.com",
      "imagine.linkedin.com",
      "itlist.linkedin.com",
      "jp.learn.linkedin.com",
      "jp.navi.linkedin.com",
      "learn.linkedin.com",
      "learning.linkedin.com",
      "legal.linkedin.com",
      "linkedinforgood.linkedin.com",
      "lists.linkedin.com",
      "live.linkedin.com",
      "manchester.linkedin.com",
      "members.linkedin.com",
      "mentor.linkedin.com",
      "mobile.linkedin.com",
      "news.linkedin.com",
      "nonprofit.linkedin.com",
      "opportunity.linkedin.com",
      "ourstory.linkedin.com",
      "partner.linkedin.com",
      "premium.linkedin.com",
      "press.linkedin.com",
      "privacy.linkedin.com",
      "projectinployment.linkedin.com",
      "purchasing.linkedin.com",
      "safety.linkedin.com",
      "sales.linkedin.com",
      "salesconnect.linkedin.com",
      "security.linkedin.com",
      "smallbusiness.linkedin.com",
      "socialimpact.linkedin.com",
      "speakers.linkedin.com",
      "stories.linkedin.com",
      "studentcareers.linkedin.com",
      "students.linkedin.com",
      "suppliers.linkedin.com",
      "talent.linkedin.com",
      "talentconnect.linkedin.com",
      "tomorrow.linkedin.com",
      "ued.linkedin.com",
      "university.linkedin.com",
      "veterans.linkedin.com",
      "volunteer.linkedin.com",
      "insiders.linkedin.com",
      "biyp.linkedin.com",
      "nonprofits.linkedin.com",
      "newsle.com",
      "www.brand.linkedin.com",
      "www.business.linkedin.com",
      "www.customersuccess.linkedin.com",
      "www.engineering.linkedin.com",
      "www.learning.linkedin.com",
      "www.legal.linkedin.com",
      "www.mobile.linkedin.com",
      "www.nonprofits.linkedin.com",
      "www.opportunity.linkedin.com",
      "www.premium.linkedin.com",
      "www.security.linkedin.com",
      "www.speakers.linkedin.com",
      "www.developer.linkedin.com"
    ],
    "days_left": 148,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.41.41",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html;charset=utf-8",
    "title": "Business Solutions on LinkedIn I LinkedIn"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": ".linkedin.com",
      "samesite": "none"
    },
    {
      "domain": "linkedin.com",
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
      "origin": "https://sub.business.linkedin.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 200
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 400",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 2,
    "notable": [],
    "sample": [
      "business.linkedin.com",
      "www.business.linkedin.com"
    ]
  },
  "cname_chain": [
    "microsites-cn.linkedin.com",
    "microsites.linkedin.com",
    "microsites.es.lnkdns.net",
    "linkedinmicrosites-gnfncuh5f0a9fgbp.z01.azurefd.net",
    "mr-z01.tm-azurefd.net"
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
      "serial": 13000630377640441863167727790405916370,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130953756e6e7976616c65311d301b060355040a13144c696e6b6564696e20436f72706f726174696f6e312430220603550403131b6166642e6d6963726f73697465732e6c696e6b6564696e2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260822000000",
      "not_after": "20270222235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/content/",
      "/*site-resources/",
      "/*site-forms/",
      "/*3qa",
      "/*3qb",
      "/*3qc",
      "/*gracias",
      "/*mercie",
      "/*grazie",
      "/*bedankt",
      "/*obrigado",
      "/*vielen-dank",
      "/me/",
      "/lem/",
      "/cx/"
    ]
  },
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 200,
    "p404_status": 404,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=31536000",
    "sitemap": {
      "urls": 8,
      "indexes": 9
    },
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
    "alt_svc": "h3=\":443\"; ma=86400",
    "cdn": [
      "CloudFront"
    ]
  },
  "elapsed_s": 16.0,
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
