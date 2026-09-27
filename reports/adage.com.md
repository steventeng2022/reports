# Security Audit Report — adage.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://adage.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | adage.com |
| Test date | 2026-09-27 02:16 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 4, Info: 20)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 19 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 20 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 21 | info | H25 | server-timing response header exposed | CWE-200 |
| 22 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 23 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 24 | info | CT1 | 41 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): usb. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-pg50pw=UwO6bTKI23RICT2yieNZizAJB; lucidlink-verification=J1CHE4K03BM1Q64NFPMW63KC24; google-site-verification=69bymnCN1yRQSpHf-DQz5sLMlqQ0GuCspakaXRLBVZg
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of adage.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://adage.com/ carries Cache-Control: private, max-age=60; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 184.26.127.138 carries PTR a184-26-127-138.deploy.static.akamaitechnologies.com. for adage.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 19. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkny57or4xkcxl.html -> 403; error page/headers match: Akamai.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 20. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for adage.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 21. [INFO] server-timing response header exposed (`H25`)

- **CWE:** CWE-200
- **Detail:** The root response of adage.com sends server-timing (cdn-cache; desc=HIT, edge; dur=1, ak_p; desc="1790475420215_3088744349_11751193_); server/edge processing metrics are disclosed to any client.
- **Recommendation:** Restrict server-timing to authenticated/debug contexts if the internals are sensitive.

### 22. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on adage.com identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 23. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of adage.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 24. [INFO] 41 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: cdn.adage.com, checkout.adage.com, checkout.arcxp-stage.adage.com, help.adage.com, jwt-api.drupal.stage.adage.com, login.adage.com, pelcro.stage.adage.com, store.adage.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "adage.com",
  "dns": {
    "a": [
      "184.26.127.138",
      "184.26.127.145"
    ],
    "aaaa": [
      "2001:b034:1c:200::d247:e338",
      "2001:b034:1c:200::d247:e348"
    ],
    "cname": null,
    "mx": [
      "usb-smtp-inbound-1.mimecast.com (pref 10)",
      "usb-smtp-inbound-2.mimecast.com (pref 60)"
    ],
    "ns": [
      "kurt.ns.cloudflare.com.",
      "connie.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "anthropic-domain-verification-pg50pw=UwO6bTKI23RICT2yieNZizAJB",
      "lucidlink-verification=J1CHE4K03BM1Q64NFPMW63KC24",
      "bw=A0toi1iKzrmRS2jxukTxOo6KI3d7V7eoIzDw5G7ubw5s",
      "google-site-verification=69bymnCN1yRQSpHf-DQz5sLMlqQ0GuCspakaXRLBVZg",
      "MS=ms52345011",
      "google-site-verification=uWzYibDTuhjliXGRiMnMEthKIS6O5mnJViVhGIOvK28",
      "v=spf1 include:spf.crain.com include:_spf.clickshare.com include:aspmx.pardot.com include:usb._netblocks.mimecast.com ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=none;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=crain.web.arc-cdn.net",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR2",
    "notBefore": "Aug 21 13:48:19 2026 GMT",
    "notAfter": "Nov 19 13:48:18 2026 GMT",
    "san": [
      "adage.com",
      "arcxp-dev.adage.com",
      "arcxp-dev.automobilwoche.de",
      "arcxp-dev.autonews.com",
      "arcxp-dev.chicagobusiness.com",
      "arcxp-dev.craincurrency.com",
      "arcxp-dev.crainscleveland.com",
      "arcxp-dev.crainsdetroit.com",
      "arcxp-dev.crainsgrandrapids.com",
      "arcxp-dev.crainsnewyork.com",
      "arcxp-dev.genomeweb.com",
      "arcxp-dev.hartenergy.com",
      "arcxp-dev.modernhealthcare.com",
      "arcxp-dev.pionline.com",
      "arcxp-dev.plasticsnews.com",
      "arcxp-dev.rubbernews.com",
      "arcxp-dev.tirebusiness.com",
      "arcxp-dev.utech-polyurethane.com",
      "arcxp-prod.automobilwoche.de",
      "arcxp-prod.craincurrency.com",
      "arcxp-prod.crainsgrandrapids.com",
      "arcxp-prod.genomeweb.com",
      "arcxp-prod.hartenergy.com",
      "arcxp-prod.modernhealthcare.com",
      "arcxp-prod.pionline.com",
      "arcxp-sandbox.adage.com",
      "arcxp-sandbox.automobilwoche.de",
      "arcxp-sandbox.autonews.com",
      "arcxp-sandbox.chicagobusiness.com",
      "arcxp-sandbox.craincurrency.com",
      "arcxp-sandbox.crainscleveland.com",
      "arcxp-sandbox.crainsdetroit.com",
      "arcxp-sandbox.crainsgrandrapids.com",
      "arcxp-sandbox.crainsnewyork.com",
      "arcxp-sandbox.genomeweb.com",
      "arcxp-sandbox.hartenergy.com",
      "arcxp-sandbox.modernhealthcare.com",
      "arcxp-sandbox.pionline.com",
      "arcxp-sandbox.plasticsnews.com",
      "arcxp-sandbox.rubbernews.com",
      "arcxp-sandbox.tirebusiness.com",
      "arcxp-sandbox.utech-polyurethane.com",
      "arcxp-stage.adage.com",
      "arcxp-stage.automobilwoche.de",
      "arcxp-stage.autonews.com",
      "arcxp-stage.chicagobusiness.com",
      "arcxp-stage.craincurrency.com",
      "arcxp-stage.crainscleveland.com",
      "arcxp-stage.crainsdetroit.com",
      "arcxp-stage.crainsgrandrapids.com",
      "arcxp-stage.crainsnewyork.com",
      "arcxp-stage.genomeweb.com",
      "arcxp-stage.hartenergy.com",
      "arcxp-stage.modernhealthcare.com",
      "arcxp-stage.pionline.com",
      "arcxp-stage.plasticsnews.com",
      "arcxp-stage.rubbernews.com",
      "arcxp-stage.tirebusiness.com",
      "arcxp-stage.utech-polyurethane.com",
      "crain-adage-dev.web.arc-cdn.net",
      "crain-adage-prod.web.arc-cdn.net",
      "crain-adage-sandbox.web.arc-cdn.net",
      "crain-adage-staging.web.arc-cdn.net",
      "crain-automobilwoche-sandbox.web.arc-cdn.net",
      "crain-automobilwoche-staging.web.arc-cdn.net",
      "crain-automotivenews-dev.web.arc-cdn.net",
      "crain-automotivenews-prod.web.arc-cdn.net",
      "crain-automotivenews-sandbox.web.arc-cdn.net",
      "crain-automotivenews-staging.web.arc-cdn.net",
      "crain-crain-dev.web.arc-cdn.net",
      "crain-crain-prod.web.arc-cdn.net",
      "crain-crain-sandbox.web.arc-cdn.net",
      "crain-crain-staging.web.arc-cdn.net",
      "crain.web.arc-cdn.net",
      "www.adage.com",
      "www.automobilwoche.de",
      "www.autonews.com",
      "www.chicagobusiness.com",
      "www.craincurrency.com",
      "www.crainscleveland.com",
      "www.crainsdetroit.com",
      "www.crainsgrandrapids.com",
      "www.crainsnewyork.com",
      "www.genomeweb.com",
      "www.hartenergy.com",
      "www.modernhealthcare.com",
      "www.pionline.com",
      "www.plasticsnews.com",
      "www.rubbernews.com",
      "www.sustainableplastics.com",
      "www.tirebusiness.com",
      "www.utech-polyurethane.com"
    ],
    "days_left": 53,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "184.26.127.138",
    "open": []
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.adage.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "source": "certspotter",
    "count": 41,
    "notable": [
      "cdn.adage.com",
      "checkout.adage.com",
      "checkout.arcxp-stage.adage.com",
      "help.adage.com",
      "jwt-api.drupal.stage.adage.com",
      "login.adage.com",
      "pelcro.stage.adage.com",
      "store.adage.com"
    ],
    "sample": [
      "a220.adage.com",
      "adage.com",
      "answers.adage.com",
      "answers.arcxp-stage.adage.com",
      "arcxp-dev.adage.com",
      "arcxp-sandbox.adage.com",
      "arcxp-stage.adage.com",
      "arcxp-stage1.adage.com",
      "c2.adage.com",
      "cdn.adage.com",
      "checkout.adage.com",
      "checkout.arcxp-stage.adage.com",
      "drupal.pelcro.adage.com",
      "drupal.piano.adage.com",
      "help.adage.com",
      "home-tmp.adage.com",
      "home.adage.com",
      "issue.adage.com",
      "jwt-api.adage.com",
      "jwt-api.arcxp-dev.adage.com"
    ]
  },
  "apex_txt": [
    "anthropic-domain-verification-pg50pw=UwO6bTKI23RICT2yieNZizAJB",
    "lucidlink-verification=J1CHE4K03BM1Q64NFPMW63KC24",
    "google-site-verification=69bymnCN1yRQSpHf-DQz5sLMlqQ0GuCspakaXRLBVZg",
    "google-site-verification=uWzYibDTuhjliXGRiMnMEthKIS6O5mnJViVhGIOvK28"
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
      "aia_ocsp": null,
      "serial": 444787563027529240304932484007310645790378,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://yr2.c.lencr.org/43.crl"
      ],
      "san": [
        "adage.com",
        "arcxp-dev.adage.com",
        "arcxp-dev.automobilwoche.de",
        "arcxp-dev.autonews.com",
        "arcxp-dev.chicagobusiness.com",
        "arcxp-dev.craincurrency.com",
        "arcxp-dev.crainscleveland.com",
        "arcxp-dev.crainsdetroit.com",
        "arcxp-dev.crainsgrandrapids.com",
        "arcxp-dev.crainsnewyork.com",
        "arcxp-dev.genomeweb.com",
        "arcxp-dev.hartenergy.com",
        "arcxp-dev.modernhealthcare.com",
        "arcxp-dev.pionline.com",
        "arcxp-dev.plasticsnews.com",
        "arcxp-dev.rubbernews.com",
        "arcxp-dev.tirebusiness.com",
        "arcxp-dev.utech-polyurethane.com",
        "arcxp-prod.automobilwoche.de",
        "arcxp-prod.craincurrency.com"
      ],
      "subject_dn": "311e301c06035504031315637261696e2e7765622e6172632d63646e2e6e6574",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595232",
      "not_before": "20260821134819",
      "not_after": "20261119134818"
    }
  },
  "x12": {
    "status": 403,
    "ptr": [
      "a184-26-127-138.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 403,
    "http_status": 403,
    "p404_status": 403,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 403,
    "crl": {
      "url": "http://yr2.c.lencr.org/43.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 403
  },
  "x16": {
    "root_status": 403,
    "server_timing": "cdn-cache; desc=HIT, edge; dur=1, ak_p; desc=\"1790475420215_3088744349_11751193_20_17415_2_8_-\";dur=1",
    "cdn": [
      "Akamai"
    ]
  },
  "x17": {},
  "elapsed_s": 5.9,
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
