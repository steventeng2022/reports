# Security Audit Report — dailycaller.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dailycaller.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dailycaller.com |
| Test date | 2026-09-27 02:24 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **27** (High: 0, Medium: 0, Low: 4, Info: 23)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P11 | WordPress login page exposed | CWE-200 |
| 15 | info | P8 | Missing security.txt | CWE-1038 |
| 16 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 17 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 21 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 22 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 23 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 24 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 25 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 26 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 27 | info | CT1 | 34 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.7.240:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.7.240:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; X-Powered-By: Express; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 15. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 16. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 17. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 18. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=R_HWsuGY5D2jhyrsiBYoNdou3xQM7mfMvmLNRIf5uNk; google-site-verification=JdrtZ9wr1Q1g22ntrYqNUiKtYX5TMbcrERLij2gcw6g; yandex-verification: a8cb98c870b639cc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of dailycaller.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 12 disallow path(s), e.g. User-agent:, User-agent:, User-agent:, User-agent:, /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 21. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xky49966shn8zj.html -> 404; error page/headers match: Cloudflare.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 22. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for dailycaller.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 23. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of dailycaller.com references 7 distinct third-party registrable domains (e.g. googleapis.com, osano.com, unwokeusadoc.com, herotozerodoc.com, workers.dev); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 24. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on dailycaller.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 25. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of dailycaller.com declares preconnect/dns-prefetch/modulepreload for 2 third-party registrable domain(s) (e.g. googleapis.com, osano.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 26. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of dailycaller.com discloses a 1-hop fronting chain (1.1 varnish (Varnish/5.2)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 27. [INFO] 34 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: git.dailycaller.com, push.cms.dailycaller.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "dailycaller.com",
  "dns": {
    "a": [
      "104.20.7.240",
      "104.20.6.240"
    ],
    "aaaa": [
      "2606:4700:10::6814:6f0",
      "2606:4700:10::6814:7f0"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx2.googlemail.com (pref 40)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 50)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "cortney.ns.cloudflare.com.",
      "nile.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=R_HWsuGY5D2jhyrsiBYoNdou3xQM7mfMvmLNRIf5uNk",
      "google-site-verification=JdrtZ9wr1Q1g22ntrYqNUiKtYX5TMbcrERLij2gcw6g",
      "v=spf1 mx ip4:74.203.48.0/23 ip4:74.203.57.0/24 ip4:174.46.206.0/23 include:amazonses.com include:spf.mandrillapp.com include:sendgrid.net include:_spf.genoomail.com include:spf.mtasv.net include:_spf.google.com ~all",
      "yandex-verification: a8cb98c870b639cc",
      "notion-domain-verification=wlPIL0HDvUMkeXcyPQiHB1EnfOwwhQ1vxpmiCcLY9w3",
      "klaviyo-site-verification=VymSM6",
      "google-site-verification=2rfEL1JNH_PfDnvN8sg2Mv121z8XI-0UrVGGBiaL3NM",
      "pinterest-site-verification=b357bf035fef44e634ab43bf435d2592",
      "google-site-verification=4AD9l3jnq_7mC91UBXtTJ2SVAQF65R2NqW2SzB0fyWY",
      "hiryanfromdisqus",
      "google-site-verification=MMCR7ys_IcnzoxvIgPvkIZqhaPjcnoD1xv6MX13EoGs",
      "facebook-domain-verification=cu97te0w4snsvnklnozd4wdzpmdusx",
      "anthropic-domain-verification-7vzw58=TbcPUP7giRsFaeMjcj5Le3Y0y",
      "brave-ledger-verification=e8997655e682114364452598541e771c9848cc4a344ed9c9381f3c95c1caf5fd",
      "dailymotion-domain-verification=dmz0onmsz1bovllha",
      "google-site-verification=aDLIgzpZsWhltTo0byY4JIrXErh2FSZC7gTNA-pcado"
    ],
    "dmarc": [
      "v=DMARC1; p=none"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=dailycaller.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  4 20:15:31 2026 GMT",
    "notAfter": "Dec  3 21:15:10 2026 GMT",
    "san": [
      "dailycaller.com",
      "meta-feed.dailycaller.com"
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
    "ip": "104.20.7.240",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "The Daily Caller"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "X-Powered-By: Express",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.dailycaller.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://dailycaller.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 404,
    "/server-status": 302,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 34,
    "notable": [
      "git.dailycaller.com",
      "push.cms.dailycaller.com"
    ],
    "sample": [
      "americansquatter.dailycaller.com",
      "blackfriday.dailycaller.com",
      "cartelvillefree.dailycaller.com",
      "charliekirk.dailycaller.com",
      "ci.dailycaller.com",
      "codetestfunnel.dailycaller.com",
      "compliance.dailycaller.com",
      "dailycaller.com",
      "damaged.dailycaller.com",
      "editorsbrief.dailycaller.com",
      "epsteinpetition.dailycaller.com",
      "epsteinpoll.dailycaller.com",
      "freeenterpriselive.dailycaller.com",
      "games.dailycaller.com",
      "git.dailycaller.com",
      "hamericansquatter.dailycaller.com",
      "hsellingsex.dailycaller.com",
      "insidececot.dailycaller.com",
      "lawlessfree.dailycaller.com",
      "liveevents.dailycaller.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=R_HWsuGY5D2jhyrsiBYoNdou3xQM7mfMvmLNRIf5uNk",
    "google-site-verification=JdrtZ9wr1Q1g22ntrYqNUiKtYX5TMbcrERLij2gcw6g",
    "yandex-verification: a8cb98c870b639cc",
    "notion-domain-verification=wlPIL0HDvUMkeXcyPQiHB1EnfOwwhQ1vxpmiCcLY9w3",
    "klaviyo-site-verification=VymSM6"
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
      "serial": 296273787706372508419469563663203793509,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/84MypdXY8WU.crl"
      ],
      "san": [
        "dailycaller.com",
        "meta-feed.dailycaller.com"
      ],
      "subject_dn": "311830160603550403130f6461696c7963616c6c65722e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260904201531",
      "not_after": "20261203211510"
    }
  },
  "http2": {
    "robots_disallow": [
      "User-agent:",
      "User-agent:",
      "User-agent:",
      "User-agent:",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
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
    "crl": {
      "url": "http://c.pki.goog/we1/84MypdXY8WU.crl",
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
    "cdn": [
      "CloudFront",
      "Fastly"
    ],
    "preconnect": [
      "googleapis.com",
      "osano.com"
    ]
  },
  "x17": {
    "via": "1.1 varnish (Varnish/5.2)"
  },
  "elapsed_s": 32.2,
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
