# Security Audit Report — sxsw.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sxsw.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | sxsw.com |
| Test date | 2026-09-27 02:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **30** (High: 0, Medium: 0, Low: 5, Info: 25)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P11 | WordPress login page exposed | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 20 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 21 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 22 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 23 | info | HTML3 | Third-party <iframe> embedded in root document | CWE-643 |
| 24 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 25 | info | HTML4 | Meta generator tag discloses site technology | CWE-200 |
| 26 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 27 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 28 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 29 | info | CT1 | 33 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 30 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx; X-Powered-By: WordPress VIP <https://wpvip.com>
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=dNdE3qz7sSGrLbC12g8ccReAFtC3Gx5dy1q9dgE_I1g; facebook-domain-verification=olbote15pv5pj5ognkycofy34mjlmz; adobe-idp-site-verification=5f299ac5ccddedab8418f37aad62a1ff499e5979c3b247bd4229
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of sxsw.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. Sitemap:
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://sxsw.com/ carries Cache-Control: max-age=300, must-revalidate; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 20. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkd8kklsffcsml.html -> 404; error page/headers match: Nginx, WordPress.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 21. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for sxsw.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 22. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of sxsw.com loads 1 cross-origin script(s) without an integrity attribute, e.g. https://cmp.osano.com/AzywLlTgj0ZEN5Fnv/1d881dc8-9a4f-47fd-9444-b5308e76584d/osano.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 23. [INFO] Third-party <iframe> embedded in root document (`HTML3`)

- **CWE:** CWE-643
- **Detail:** Root document of sxsw.com embeds 1 cross-origin iframe(s), e.g. https://www.googletagmanager.com/ns.html?id=GTM-WB7Z9Q5; embedded origins are framed inside the page with its trust context.
- **Recommendation:** Review embedded origins and consider sandbox attributes.

### 24. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on sxsw.com lists 5 <loc> URL(s) across 6 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 25. [INFO] Meta generator tag discloses site technology (`HTML4`)

- **CWE:** CWE-200
- **Detail:** Root document of sxsw.com declares generator: WordPress 7.1.2; generator tags fingerprint the site builder/CMS for targeted attacks.
- **Recommendation:** Remove the generator meta tag or keep it consistent with the deployed version.

### 26. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of sxsw.com references 5 distinct third-party registrable domains (e.g. w3.org, googletagmanager.com, wordpress.com, osano.com, w.org); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 27. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on sxsw.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 28. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of sxsw.com declares preconnect/dns-prefetch/modulepreload for 2 third-party registrable domain(s) (e.g. hs-scripts.com, parsely.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 29. [INFO] 33 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: staging.image-manager.sxsw.com, staging.sxsw.com, support.sxsw.com, www.staging.sxsw.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 30. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: staging.image-manager.sxsw.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "sxsw.com",
  "dns": {
    "a": [
      "192.0.66.144"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 1)"
    ],
    "ns": [
      "ns-1453.awsdns-53.org.",
      "ns-1565.awsdns-03.co.uk.",
      "ns-205.awsdns-25.com.",
      "ns-1002.awsdns-61.net."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=dNdE3qz7sSGrLbC12g8ccReAFtC3Gx5dy1q9dgE_I1g",
      "v=DMARC1; p=reject; rua=mailto:dmarc-aggregate@; pct=100",
      "ZOOM_verify_a9DO-VMYQS64sNgz2Xh-5w",
      "facebook-domain-verification=olbote15pv5pj5ognkycofy34mjlmz",
      "adobe-idp-site-verification=5f299ac5ccddedab8418f37aad62a1ff499e5979c3b247bd4229ca57071848e8",
      "v=spf1 ip4:66.219.52.0/24 ip4:134.128.92.11 include:_spf.google.com include:_festivalprospf.sxsw.com include:_spf.createsend.com include:mail.zendesk.com include:558236.spf02.hubspotemail.net include:spf.mandrillapp.com include:amazonses.com ~all",
      "apple-domain-verification=zeJgTan8Yy8t07ga"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:dmarc_admin@sxsw.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=sxsw.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep 23 09:42:07 2026 GMT",
    "notAfter": "Dec 22 09:42:06 2026 GMT",
    "san": [
      "sxsw.com",
      "www.sxsw.com"
    ],
    "days_left": 86,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.144",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Homepage - SXSW"
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx",
    "X-Powered-By: WordPress VIP <https://wpvip.com>"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.sxsw.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://sxsw.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 301,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 33,
    "notable": [
      "staging.image-manager.sxsw.com",
      "staging.sxsw.com",
      "support.sxsw.com",
      "www.staging.sxsw.com"
    ],
    "sample": [
      "airwatch.sxsw.com",
      "books.sxsw.com",
      "email.expomail.sxsw.com",
      "event-svc-pvt.sxsw.com",
      "explore.sxsw.com",
      "expo.sxsw.com",
      "expos.sxsw.com",
      "filmlibrary.sxsw.com",
      "gamingblog.sxsw.com",
      "gamingexplore.sxsw.com",
      "hub.sxsw.com",
      "id.sxsw.com",
      "image-manager.sxsw.com",
      "kylo.sxsw.com",
      "leads.sxsw.com",
      "links.sxsw.com",
      "mentors.sxsw.com",
      "merch.sxsw.com",
      "online.sxsw.com",
      "participate.sxsw.com"
    ],
    "dangling": [
      "staging.image-manager.sxsw.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=dNdE3qz7sSGrLbC12g8ccReAFtC3Gx5dy1q9dgE_I1g",
    "facebook-domain-verification=olbote15pv5pj5ognkycofy34mjlmz",
    "adobe-idp-site-verification=5f299ac5ccddedab8418f37aad62a1ff499e5979c3b247bd4229",
    "apple-domain-verification=zeJgTan8Yy8t07ga"
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
      "aia_ocsp": null,
      "serial": 591144306678755171075819465826390646948450,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://ye1.c.lencr.org/99.crl"
      ],
      "san": [
        "sxsw.com",
        "www.sxsw.com"
      ],
      "subject_dn": "3111300f06035504031308737873772e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594531",
      "not_before": "20260923094207",
      "not_after": "20261222094206"
    }
  },
  "http2": {
    "robots_disallow": [
      "Sitemap:"
    ]
  },
  "x12": {
    "status": 200
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
    "sitemap": {
      "urls": 5,
      "indexes": 6
    },
    "crl": {
      "url": "http://ye1.c.lencr.org/99.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "cdn": [
      "Fastly"
    ],
    "preconnect": [
      "hs-scripts.com",
      "parsely.com"
    ]
  },
  "x17": {},
  "elapsed_s": 28.7,
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
