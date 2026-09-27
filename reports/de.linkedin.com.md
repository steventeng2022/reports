# Security Audit Report — de.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://de.linkedin.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | de.linkedin.com |
| Test date | 2026-09-27 02:24 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **25** (High: 0, Medium: 0, Low: 3, Info: 22)

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
| 10 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 11 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 12 | info | CK5 | Cookie scoped to parent domain (linkedin.com) | CWE-200 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 15 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 16 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 17 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 18 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 19 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 20 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 21 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 22 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 23 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 24 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 25 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.146.215:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.146.215:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Java session cookie (J2EE); Cloudflare CDN/WAF
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

### 10. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but de.linkedin.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 11. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'JSESSIONID' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 12. [INFO] Cookie scoped to parent domain (linkedin.com) (`CK5`)

- **CWE:** CWE-200
- **Detail:** Set-Cookie Domain attribute is broader than the request host de.linkedin.com.
- **Recommendation:** Confirm the wider cookie scope is intended.

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 4398 disallow path(s), e.g. /addContacts*, /addressBookExport*, /ambry, /analytics/, /answers*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of de.linkedin.com permits unsafe-inline; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 15. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of de.linkedin.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 16. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on de.linkedin.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 17. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkfx9jqzyvmryl.html -> 404; error page/headers match: Cloudflare.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 18. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on de.linkedin.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 19. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on de.linkedin.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of de.linkedin.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 20. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of de.linkedin.com loads 2 cross-origin script(s) without an integrity attribute, e.g. https://static.licdn.com/aero-v1/sc/h/azyj0u7xl6tpxe5fn3t3djk7p, https://static.licdn.com/aero-v1/sc/h/26g24klhu4k9p8zgtz6fs4k01; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 21. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on de.linkedin.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 22. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of de.linkedin.com sends a CSP but contains 1 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 23. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of de.linkedin.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 24. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on de.linkedin.com identify the edge as CloudFront; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 25. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of de.linkedin.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "de.linkedin.com",
  "dns": {
    "a": [
      "172.64.146.215",
      "104.18.41.41"
    ],
    "aaaa": [
      "2a06:98c1:3109::6812:2929",
      "2a06:98c1:310b::ac40:92d7"
    ],
    "cname": "cctld.linkedin.com.",
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
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=ac.linkedin.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Sep  3 00:00:00 2026 GMT",
    "notAfter": "Mar  3 23:59:59 2027 GMT",
    "san": [
      "ac.linkedin.com",
      "ad.linkedin.com",
      "ae.linkedin.com",
      "af.linkedin.com",
      "ag.linkedin.com",
      "ai.linkedin.com",
      "al.linkedin.com",
      "am.linkedin.com",
      "an.linkedin.com",
      "ao.linkedin.com",
      "ap.linkedin.com",
      "aq.linkedin.com",
      "ar.linkedin.com",
      "as.linkedin.com",
      "at.linkedin.com",
      "au.linkedin.com",
      "aw.linkedin.com",
      "ax.linkedin.com",
      "az.linkedin.com",
      "ba.linkedin.com",
      "bb.linkedin.com",
      "bd.linkedin.com",
      "be.linkedin.com",
      "bf.linkedin.com",
      "bg.linkedin.com",
      "bh.linkedin.com",
      "bi.linkedin.com",
      "bj.linkedin.com",
      "bl.linkedin.com",
      "bm.linkedin.com",
      "bn.linkedin.com",
      "bo.linkedin.com",
      "br.linkedin.com",
      "bs.linkedin.com",
      "bt.linkedin.com",
      "bu.linkedin.com",
      "bv.linkedin.com",
      "bw.linkedin.com",
      "bx.linkedin.com",
      "by.linkedin.com",
      "bz.linkedin.com",
      "ca.linkedin.com",
      "cc.linkedin.com",
      "cd.linkedin.com",
      "cf.linkedin.com",
      "cg.linkedin.com",
      "ch.linkedin.com",
      "ci.linkedin.com",
      "ck.linkedin.com",
      "cl.linkedin.com",
      "cm.linkedin.com",
      "cn.linkedin.com",
      "co.linkedin.com",
      "cp.linkedin.com",
      "cr.linkedin.com",
      "ct.linkedin.com",
      "cu.linkedin.com",
      "cv.linkedin.com",
      "cw.linkedin.com",
      "cx.linkedin.com",
      "cy.linkedin.com",
      "cz.linkedin.com",
      "dd.linkedin.com",
      "de.linkedin.com",
      "dg.linkedin.com",
      "dj.linkedin.com",
      "dk.linkedin.com",
      "dm.linkedin.com",
      "do.linkedin.com",
      "dy.linkedin.com",
      "dz.linkedin.com",
      "ea.linkedin.com",
      "ec.linkedin.com",
      "ee.linkedin.com",
      "ef.linkedin.com",
      "eg.linkedin.com",
      "eh.linkedin.com"
    ],
    "days_left": 157,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.146.215",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "LinkedIn: Einloggen oder anmelden"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Java session cookie (J2EE)",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": ".de.linkedin.com",
      "samesite": "none"
    },
    {
      "domain": "linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".de.linkedin.com",
      "samesite": "none"
    },
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
      "origin": "https://sub.de.linkedin.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://de.linkedin.com/hp"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 400",
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
  "cname_chain": [
    "cctld.linkedin.com",
    "cctld.es.lnkdns.net",
    "www.linkedin.com.cdn.cloudflare.net"
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
      "serial": 15582316231590459497317703016434957173,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "ac.linkedin.com",
        "ad.linkedin.com",
        "ae.linkedin.com",
        "af.linkedin.com",
        "ag.linkedin.com",
        "ai.linkedin.com",
        "al.linkedin.com",
        "am.linkedin.com",
        "an.linkedin.com",
        "ao.linkedin.com",
        "ap.linkedin.com",
        "aq.linkedin.com",
        "ar.linkedin.com",
        "as.linkedin.com",
        "at.linkedin.com",
        "au.linkedin.com",
        "aw.linkedin.com",
        "ax.linkedin.com",
        "az.linkedin.com",
        "ba.linkedin.com"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311230100603550407130953756e6e7976616c65311d301b060355040a13144c696e6b6564696e20436f72706f726174696f6e311830160603550403130f61632e6c696e6b6564696e2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260903000000",
      "not_after": "20270303235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/addContacts*",
      "/addressBookExport*",
      "/ambry",
      "/analytics/",
      "/answers*",
      "/authwall",
      "/badges/profile/create",
      "/cap/",
      "/chat/",
      "/checkpoint/",
      "/companyDir*",
      "/connections*",
      "/csp/",
      "/e/",
      "/edurec*"
    ]
  },
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/apple-app-site-association",
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
    "root_status": 200,
    "hsts": "max-age=31536000",
    "security_txt": "/.well-known/security.txt",
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
  "x17": {
    "ocsp_http": "http://ocsp.digicert.com"
  },
  "elapsed_s": 16.2,
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
