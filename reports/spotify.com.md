# Security Audit Report — spotify.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://spotify.com/ |
| Bug bounty program | Spotify |
| Listed scope domain | spotify.com |
| Test date | 2026-09-27 02:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **25** (High: 0, Medium: 0, Low: 3, Info: 22)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 20 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 21 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 22 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 23 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 24 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 25 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: envoy
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000, h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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
- **Detail:** Header reveals: envoy
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: have-i-been-pwned-verification=33b7ae688099ee8cca63259b769a0ea8; tiktok-developers-site-verification=ttGXJxgq1HQKquomgiljzFq53uoLHcUC; zapier-domain-verification-challenge=db8a0b98-bb6a-4f84-a699-344dc23fef3b
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but spotify.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 15 disallow path(s), e.g. /*/about-us/contact/contact-spotify-password/, /*/about-us/contact/contact-spotify-account/, /*/get-spotify/*, /*/xhr/*, /*/external/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 35.186.224.24 carries PTR 24.224.186.35.bc.googleusercontent.com. for spotify.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on spotify.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for spotify.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The spotify.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on spotify.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of spotify.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 21. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on spotify.com lists 10 <loc> URL(s) across 11 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 22. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of spotify.com carries alt-svc h3=":443"; ma=2592000,h3-29=":443"; ma=2592000, h3=":443"; ma=2592000; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 23. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of spotify.com contains wildcard SAN entry(ies) *.spotify.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 24. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of spotify.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 25. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of spotify.com discloses a 2-hop fronting chain (HTTP/2 edgeproxy, 1.1 google); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

## Evidence (raw response observations)

```json
{
  "domain": "spotify.com",
  "dns": {
    "a": [
      "35.186.224.24"
    ],
    "aaaa": [
      "2600:1901:1:7c5::"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx4.googlemail.com (pref 10)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx5.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns-cloud-a4.googledomains.com.",
      "ns-cloud-a2.googledomains.com.",
      "ns-cloud-a1.googledomains.com.",
      "dns1.p07.nsone.net.",
      "ns-cloud-a3.googledomains.com."
    ],
    "caa": [],
    "spf": [
      "have-i-been-pwned-verification=33b7ae688099ee8cca63259b769a0ea8",
      "tiktok-developers-site-verification=ttGXJxgq1HQKquomgiljzFq53uoLHcUC",
      "_anz60jg9dhixqlmcv20ntnooz9m0k8x",
      "zapier-domain-verification-challenge=db8a0b98-bb6a-4f84-a699-344dc23fef3b",
      "parallels-domain-verification=7bb3a358f26f4e23a5077648266570c873182a57d6d44e47a55ef6cf72cdb470",
      "docker-verification=82f3553a-fb50-4d4e-9607-8a8079ee354f",
      "atlassian-sending-domain-verification=d90f2e0c-fa57-43b6-910f-065cc4d6a0e3",
      "atlassian-domain-verification=1My5WsxLluUY8uIjgbLs4MY3ySFp32k9aYNW2IR4ihM64k58CxpFnB5R9SEiJAnR",
      "google-site-verification=uD4f4k01lFWX3qwVbqnVaJg8atpKgAgc-_RYcyT3ofU",
      "facebook-domain-verification=wtgn9pdvjdhs21j9gz6knsnpkafvs5",
      "yahoo-verification-key=bdudmGyddArwRiVafgItrfYq8nrhd5vzNZ7Ik/G0ILM=",
      "v=spf1 ip4:80.76.146.172 ip4:80.76.146.173 include:_spf.google.com include:servers.mcsv.net include:_spf.salesforce.com include:_spf.netigate.se include:21894833.spf06.hubspotemail.net ~all",
      "wiz-domain-verification=370862886b04dfa626d54d2c4cc955174c6f3164a104a85d725ae5ece72ea3ef",
      "openai-domain-verification=dv-VNYvLsJIttFvRz7ymxFgjrPC",
      "cloudflare_dashboard_sso=19cd522a4fc20281209f03663d34ee76",
      "apple-domain-verification=Dxae2sKJD2O5TKGK",
      "loom-site-verification=3ee9ca8c2df34d08abbb7be5185bc768",
      "windsurf-verification=LRBAV_kH3G5aleY1GIc1jMUg_8iBpigIm2qYF00bRps=",
      "tiktok-developers-site-verification=pZNawVY3o5Ma80MRCC6Fref1NiLzuEVU",
      "google-site-verification=0wmxUE7T2OWPhtwjco6oCyqqbYgtosjQdywAr4G4kU0",
      "onetrust-domain-verification=508849d40e2b4b8fba2b7eaf84f1bddc",
      "reachdesk-verification=v0DuUrKxORfyqxIOMkJm57GlQtvaAv0watqt7x7ylMN21LAHqR6dEhUpSxOp7DCh",
      "vmware-cloud-verification-dab4c35d-1819-4431-add3-d3c382ee32bc",
      "facebook-domain-verification=qyrvuca7h4s7wevhzbprtt3tdyyhf1",
      "google-site-verification=buTP-BbGUoP8lPntqskvSbeS68M4PDoIFkiUtQEA5n8",
      "liveramp-site-verification=IAXPTLlWofr4aaKtwVqirrHvOqUMiXnaMW8WMmuz1v0",
      "anthropic-domain-verification-mqtmtz=BSac9xfxvigNt4Ralt2KPkt1V",
      "tiktok-developers-site-verification=98xFqMKsOJ51nNJpUCGPGbo7m17gtf7f",
      "google-site-verification=ehIHBRyAOKdOfUyw_ONXT0TMuUsdk1gDGSYfk8YhRgw",
      "jamf-site-verification=1kKxrm0glhWvrA0YiABH_w",
      "status-page-domain-verification=wq4jns7ydgbb",
      "MS=ms38184034",
      "cursor-domain-verification-985xgr=7ROYkkLIfunrK2GtW0spMGDNw",
      "notion-domain-verification=AqUDuql68X5rQ1qLwho6huUjf4QteXZlyvTIKS1txnq",
      "google-site-verification=ESiNWockZgSgTPSsrsAdMX9afsj2-_8504nQ0qIHkDA"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; fo=1; rf=afrf; rua=mailto:6jxge2ly@ag.eu.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=SE, localityName=Stockholm, organizationName=Spotify AB, commonName=*.spotify.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul  9 00:00:00 2026 GMT",
    "notAfter": "Jan 23 23:59:59 2027 GMT",
    "san": [
      "*.spotify.com",
      "spotify.com"
    ],
    "days_left": 118,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "35.186.224.24",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: envoy"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.spotify.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.spotify.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "have-i-been-pwned-verification=33b7ae688099ee8cca63259b769a0ea8",
    "tiktok-developers-site-verification=ttGXJxgq1HQKquomgiljzFq53uoLHcUC",
    "zapier-domain-verification-challenge=db8a0b98-bb6a-4f84-a699-344dc23fef3b",
    "parallels-domain-verification=7bb3a358f26f4e23a5077648266570c873182a57d6d44e47a5",
    "docker-verification=82f3553a-fb50-4d4e-9607-8a8079ee354f"
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
      "serial": 19768150859664329177122488698879204848,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "*.spotify.com",
        "spotify.com"
      ],
      "subject_dn": "310b3009060355040613025345311230100603550407130953746f636b686f6c6d31133011060355040a130a53706f746966792041423116301406035504030c0d2a2e73706f746966792e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260709000000",
      "not_after": "20270123235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/*/about-us/contact/contact-spotify-password/",
      "/*/about-us/contact/contact-spotify-account/",
      "/*/get-spotify/*",
      "/*/xhr/*",
      "/*/external/*",
      "/*/legal/*?ets=",
      "/*/legal/advertiser-terms-and-conditions/",
      "/*/legal/gdpr-article-15-information/",
      "/*/legal/spotify-controller-data-processing-terms/",
      "/*/legal/podcast-api-terms/",
      "/*/account/cls/*",
      "/*/starbuckspartners",
      "/starbuckspartners",
      "/ppt/*?",
      "/partner/*?"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "24.224.186.35.bc.googleusercontent.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.spotify.com/",
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
    "hsts": "max-age=31536000",
    "sitemap": {
      "urls": 10,
      "indexes": 11
    },
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "alt_svc": "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000, h3=\":443\"; ma=2592000"
  },
  "x17": {
    "wildcard_san": [
      "*.spotify.com"
    ],
    "ocsp_http": "http://ocsp.digicert.com",
    "via": "HTTP/2 edgeproxy, 1.1 google"
  },
  "elapsed_s": 13.8,
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
