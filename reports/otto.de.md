# Security Audit Report — otto.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://otto.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | otto.de |
| Test date | 2026-09-27 01:29 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

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
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 20 | info | CT1 | 33 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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
- **Detail:** Detected: Server: Varnish
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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: mongodb-site-verification=XP5hVwaaialm2di9r4ME8FEBAgoydmWc; wiz-domain-verification=9e685f8b43ce318887c925c4c1973c62ec374a09e49fb1c22bfb049a; miro-verification=bdc9cd9f80167223093040082fce9f70cb15a22c
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 14 disallow path(s), e.g. /gate/, /onex/, /cdn-cgi/, /149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/, /suche/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 63.184.231.210 carries PTR ec2-63-184-231-210.eu-central-1.compute.amazonaws.com. for otto.de.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for otto.de, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The otto.de certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [INFO] 33 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: analyzer-ui.develop.prada-dr.cloud.otto.de, api.permissionservice.nonlive.ipanema.cloud.otto.de, cdc.develop.paymentinfo.cloud.otto.de, configuration-ui.develop.prada-dr.cloud.otto.de, develop.customer-green.cloud.otto.de, develop.tracking-dr.cloud.otto.de, external-api.permissionservice.nonlive.ipanema.cloud.otto.de, infra.identity-green.cloud.otto.de, infra.tracking-dr.cloud.otto.de, internal-api.permissionservice.nonlive.ipanema.cloud.otto.de
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "otto.de",
  "dns": {
    "a": [
      "63.184.231.210",
      "63.185.195.55",
      "63.181.40.227"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "otto-de.mail.protection.outlook.com (pref 50)"
    ],
    "ns": [
      "a24-65.akam.net.",
      "a9-64.akam.net.",
      "a8-65.akam.net.",
      "a28-66.akam.net.",
      "a5-66.akam.net.",
      "a1-208.akam.net."
    ],
    "caa": [],
    "spf": [
      "mongodb-site-verification=XP5hVwaaialm2di9r4ME8FEBAgoydmWc",
      "wiz-domain-verification=9e685f8b43ce318887c925c4c1973c62ec374a09e49fb1c22bfb049a03ddf05e",
      "MS=ms67614880",
      "QCbesHKcvkL0B5iRm1w3tj7P1PyQAorD",
      "miro-verification=bdc9cd9f80167223093040082fce9f70cb15a22c",
      "00D9b00000SfmQL=1TB9b00000008wr;00D2o000000kAmU=1TBTr00000004Jl",
      "google-site-verification=uhp66_5IP66csx6AefbIEaCUbgfvZ6gffnAwJj3IX5c",
      "apple-domain-verification=siseb2WuYlAhQ1Js",
      "wiz-domain-verification=084961cf6a9943467022b6e4e254206d89ccca15ebf3b26fbcda38cfa76fdb97",
      "w/u0tIPwCWqtaT33cfLaDRI4cUHazVnFGfjZSvZs5J409OjBQgoS6SifMXSef28udDpQymTVQsX2gktjmDFz0w==",
      "facebook-domain-verification=j70v29fpjg4ojg80gbifqw1eego33r",
      "atlassian-domain-verification=XuvfFNPt8O1LGWHgmu6drxqQRbfQGX4Dr2Ot8f9rgaA2FemHHZpmo2KZHiug8I9G",
      "v=spf1 ip4:80.85.192.0/20 include:spf.hornetsecurity.com include:spf.protection.outlook.com include:_spf.salesforce.com a:_spf.otto.de -all",
      "dtm-domain-verification=mM876KNtSp0KQQYotikNG6TPTIoaSmKM_7lgUENJM_o",
      "figma-domain-verification=a7779162ff855ae8f5aca8708caa598f1d994bcd54c597f3816230fcc8817fe0-1744186662",
      "amazonses:mIH7OVHQO2F5WChOVyD79u9apTHT6sbf7e2VZ9NtvsA=",
      "adobe-idp-site-verification=86e3d89586a3c84e183be6ac5f4ecb05d1011a5b6df236931e040666450a8c7f",
      "CTxuSaM2ovKYyOHyjzvyQ0f9brbx1ug7SugtgTUplebg9BFi1Vtkj5o/qoiuVxKuAUUWEaoNuR4awzrsYh6LiA==",
      "google-site-verification=mwRR8O8tb2xn2nbAuVoFRXq3FvQG8TBXVfvao9Ws6dY",
      "docker-verification=dd370709-def2-48e6-bfe6-ceafcf66e031"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=DE, localityName=Hamburg, organizationName=Otto GmbH & Co. KGaA, commonName=www.otto.de",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Feb 12 00:00:00 2026 GMT",
    "notAfter": "Mar 15 23:59:59 2027 GMT",
    "san": [
      "www.otto.de",
      "pxc.otto.de",
      "ts.otto.de",
      "otto.de"
    ],
    "days_left": 169,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "63.184.231.210",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.otto.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://otto.de:443/"
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
    "count": 33,
    "notable": [
      "analyzer-ui.develop.prada-dr.cloud.otto.de",
      "api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "cdc.develop.paymentinfo.cloud.otto.de",
      "configuration-ui.develop.prada-dr.cloud.otto.de",
      "develop.customer-green.cloud.otto.de",
      "develop.tracking-dr.cloud.otto.de",
      "external-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "infra.identity-green.cloud.otto.de",
      "infra.tracking-dr.cloud.otto.de",
      "internal-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "linkenrichment.nonlive.ipanema.cloud.otto.de",
      "live.customer-green.cloud.otto.de",
      "nl-unsub-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "qs-ui.develop.prada-dr.cloud.otto.de",
      "teaserui.develop.up.cloud.otto.de"
    ],
    "sample": [
      "analyzer-ui.develop.prada-dr.cloud.otto.de",
      "api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "cass.cccs.dr.orderprocessing.otto.de",
      "cdc.develop.paymentinfo.cloud.otto.de",
      "cecuda.cccs.dr.orderprocessing.otto.de",
      "configuration-ui.develop.prada-dr.cloud.otto.de",
      "contracts-wm.int.marketplace-integration.platform.otto.de",
      "contracts.live.marketplace-integration.platform.otto.de",
      "craproxy.cccs.dr.orderprocessing.otto.de",
      "customerscoring.cccs.dr.orderprocessing.otto.de",
      "designsystem.digitalretail.otto.de",
      "develop.customer-green.cloud.otto.de",
      "develop.tracking-dr.cloud.otto.de",
      "digitalretail.otto.de",
      "external-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "infra.identity-green.cloud.otto.de",
      "infra.tracking-dr.cloud.otto.de",
      "internal-api.permissionservice.nonlive.ipanema.cloud.otto.de",
      "linkenrichment.nonlive.ipanema.cloud.otto.de",
      "live.customer-green.cloud.otto.de"
    ]
  },
  "apex_txt": [
    "mongodb-site-verification=XP5hVwaaialm2di9r4ME8FEBAgoydmWc",
    "wiz-domain-verification=9e685f8b43ce318887c925c4c1973c62ec374a09e49fb1c22bfb049a",
    "miro-verification=bdc9cd9f80167223093040082fce9f70cb15a22c",
    "google-site-verification=uhp66_5IP66csx6AefbIEaCUbgfvZ6gffnAwJj3IX5c",
    "apple-domain-verification=siseb2WuYlAhQ1Js"
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
      "serial": 12473310547766822285006445669020459610,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b30090603550406130244453110300e0603550407130748616d62757267311d301b060355040a0c144f74746f20476d6248202620436f2e204b476141311430120603550403130b7777772e6f74746f2e6465",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260212000000",
      "not_after": "20270315235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/gate/",
      "/onex/",
      "/cdn-cgi/",
      "/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/",
      "/suche/",
      "/gate/",
      "/onex/",
      "/cdn-cgi/",
      "/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/",
      "/kundenbewertungen/",
      "/gate/",
      "/onex/",
      "/cdn-cgi/",
      "/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-63-184-231-210.eu-central-1.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.otto.de/",
    "http_status": 301,
    "p404_status": 301,
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
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
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
  "elapsed_s": 41.4,
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
