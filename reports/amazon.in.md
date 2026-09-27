# Security Audit Report — amazon.in

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.in/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.in |
| Test date | 2026-09-27 02:18 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 4, Info: 20)

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
| 18 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 20 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 21 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 22 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 23 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 24 | info | CT1 | 120 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Server
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
- **Detail:** Header reveals: Server
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=xibV-ooZgBwkpinWNuETXl-tasUI80Q4nxnNQVqE8cw; liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo; google-site-verification=GsLI5kBVqu0oRPMAr-bFqvv3FRTlCiHyYQ2VUGDNwHM
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 248 disallow path(s), e.g. */s?k=*&rh=n*p_*p_*p_, /dp/product-availability/, /dp/rate-this-item/, /exec/obidos/account-access-login, /exec/obidos/change-style
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.253.168.43 carries PTR ec2-3-253-168-43.eu-west-1.compute.amazonaws.com. for amazon.in.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on amazon.in; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for amazon.in, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The amazon.in certificate lists an AIA OCSP responder (http://ocsp.r2m04.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 21. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of amazon.in contains wildcard SAN entry(ies) *.cy.peg.a2z.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 22. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of amazon.in is http://ocsp.r2m04.amazontrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 23. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of amazon.in declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 24. [INFO] 120 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.eu-west-1.prod.proxy.live.amazon.in, beta.buywithamazon.amazon.in, beta.gql.music.amazon.in, docs.amazonpay.amazon.in, help.amazon.in, pay.amazon.in, support.amazon.in
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.in",
  "dns": {
    "a": [
      "3.253.168.43",
      "3.253.170.100",
      "3.253.176.101"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns1.amzndns.co.uk.",
      "ns1.amzndns.com.",
      "ns2.amzndns.co.uk.",
      "ns2.amzndns.org.",
      "ns1.amzndns.org.",
      "ns2.amzndns.net.",
      "ns2.amzndns.com.",
      "ns1.amzndns.net."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=xibV-ooZgBwkpinWNuETXl-tasUI80Q4nxnNQVqE8cw",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "google-site-verification=GsLI5kBVqu0oRPMAr-bFqvv3FRTlCiHyYQ2VUGDNwHM",
      "spf2.0/pra include:amazon.com -all",
      "MS=ms65650497",
      "google-gws-recovery-domain-verification=69979608",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "google-gws-recovery-domain-verification=70440648",
      "canva-site-verification=hbDzfqg-Yto5mQswKAEatA",
      "google-site-verification=ABRnURlPVtQRBIMqadgOhBTXsxY_HxEn04unYT9D0J4",
      "adobe-idp-site-verification=b6bcd3e5aaffc63607c8bf75744d9a0d1febc50dd7f389428e2ae476c9ba8814",
      "v=spf1 include:amazon.com -all",
      "docker-verification=18325118-b0dc-40bd-81c5-d6aafedf278c",
      "bluebeam-verification=nbh9t8rjoaej9iluzr8knu56ehfv84",
      "TS1760027",
      "google-site-verification=xTaP4clXFdYM8wMNQRgr5Ezb9b9STzHgq4tmVyZrDEI",
      "kahoot-domain-verification=c1ef4a458d927fa9054ae24946b2228c246e07972ce6e8a8ad017acf06c434f4",
      "MS=ms27803002",
      "facebook-domain-verification=hgfnhz04meuxr62da6b00kwas2n4md"
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=quarantine;",
      "pct=100;",
      "rua=mailto:report@dmarc.amazon.com;",
      "ruf=mailto:report@dmarc.amazon.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.cy.peg.a2z.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 11 00:00:00 2026 GMT",
    "notAfter": "Feb 24 23:59:59 2027 GMT",
    "san": [
      "*.cy.peg.a2z.com",
      "www.amazon.co.in",
      "p-y3-www-amazon-in-kalias.amazon.in",
      "p-yo-www-amazon-in-kalias.amazon.in",
      "origin-www.amazon.in",
      "amazon.in",
      "edgeflow-dp.aero.c95e7e602-frontier.amazon.in",
      "amazon.co.in",
      "edgeflow.aero.c95e7e602-frontier.amazon.in",
      "p-nt-www-amazon-in-kalias.amazon.in",
      "www.amazon.in"
    ],
    "days_left": 150,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.253.168.43",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Server"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.amazon.in",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.in/"
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
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 120,
    "notable": [
      "api.eu-west-1.prod.proxy.live.amazon.in",
      "beta.buywithamazon.amazon.in",
      "beta.gql.music.amazon.in",
      "docs.amazonpay.amazon.in",
      "help.amazon.in",
      "pay.amazon.in",
      "support.amazon.in"
    ],
    "sample": [
      "aam.amazon.in",
      "aan.amazon.in",
      "aax-eu.amazon.in",
      "abintegrations.amazon.in",
      "accelerator.amazon.in",
      "account-status.amazon.in",
      "account.kep.amazon.in",
      "al-eu-apiproxy.amazon.in",
      "alexa-skills-beta-eu.amazon.in",
      "alexa-skills-beta.amazon.in",
      "alexa-skills-na.amazon.in",
      "alexa-smart-nudge.amazon.in",
      "alm.amazon.in",
      "amazon.in",
      "amazonpay-insurance.amazon.in",
      "amazonpay-sandbox.amazon.in",
      "ams.amazon.in",
      "api.eu-west-1.prod.proxy.live.amazon.in",
      "arcus-www.amazon.in",
      "asmw.amazon.in"
    ]
  },
  "apex_txt": [
    "google-site-verification=xibV-ooZgBwkpinWNuETXl-tasUI80Q4nxnNQVqE8cw",
    "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
    "google-site-verification=GsLI5kBVqu0oRPMAr-bFqvv3FRTlCiHyYQ2VUGDNwHM",
    "google-gws-recovery-domain-verification=69979608",
    "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbD"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 17616827723461330406500846142880299789,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "san": [
        "*.cy.peg.a2z.com",
        "www.amazon.co.in",
        "p-y3-www-amazon-in-kalias.amazon.in",
        "p-yo-www-amazon-in-kalias.amazon.in",
        "origin-www.amazon.in",
        "amazon.in",
        "edgeflow-dp.aero.c95e7e602-frontier.amazon.in",
        "amazon.co.in",
        "edgeflow.aero.c95e7e602-frontier.amazon.in",
        "p-nt-www-amazon-in-kalias.amazon.in",
        "www.amazon.in"
      ],
      "subject_dn": "3119301706035504030c102a2e63792e7065672e61327a2e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20260811000000",
      "not_after": "20270224235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "*/s?k=*&rh=n*p_*p_*p_",
      "/dp/product-availability/",
      "/dp/rate-this-item/",
      "/exec/obidos/account-access-login",
      "/exec/obidos/change-style",
      "/exec/obidos/dt/assoc/handle-buy-box",
      "/exec/obidos/flex-sign-in",
      "/exec/obidos/handle-buy-box",
      "/exec/obidos/refer-a-friend-login",
      "/exec/obidos/subst/associates/join",
      "/exec/obidos/subst/marketplace/sell-your-collection.html",
      "/exec/obidos/subst/marketplace/sell-your-stuff.html",
      "/exec/obidos/subst/partners/friends/access.html",
      "/exec/obidos/tg/cm/member/",
      "/gp/cart"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-3-253-168-43.eu-west-1.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.amazon.in/",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {
    "wildcard_san": [
      "*.cy.peg.a2z.com"
    ],
    "ocsp_http": "http://ocsp.r2m04.amazontrust.com"
  },
  "elapsed_s": 42.3,
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
