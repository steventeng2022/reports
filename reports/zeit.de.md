# Security Audit Report — zeit.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zeit.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | zeit.de |
| Test date | 2026-09-27 02:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 20 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: klaviyo-site-verification=VfVpZ3; _globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A; apple-domain-verification=TYlrXCrrWPMzHzAY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of zeit.de has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but zeit.de is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 43 disallow path(s), e.g. /angebote/, /zeit/, /suche/, /templates/, /hp_channels/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.40.5.50 carries PTR 50.5.40.34.bc.googleusercontent.com. for zeit.de.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association on zeit.de; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for zeit.de, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on zeit.de has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of zeit.de.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 20. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on zeit.de lists 3162 <loc> URL(s) across 3163 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "zeit.de",
  "dns": {
    "a": [
      "34.40.5.50"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "zeit-de.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "dns2.p01.nsone.net.",
      "dns3.p01.nsone.net.",
      "dns1.p01.nsone.net.",
      "dns4.p01.nsone.net."
    ],
    "caa": [],
    "spf": [
      "MS=ms37100824",
      "gxg1t2ljzzj4n05h57kh5bvsxjr1ctcp",
      "klaviyo-site-verification=VfVpZ3",
      "v=spf1 mx include:spf1.zeit.de include:spf.mailjet.com include:sendgrid.net include:spf.mandrillapp.com include:spfa.myconvento.com include:spf.protection.outlook.com ~all",
      "_globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A",
      "apple-domain-verification=TYlrXCrrWPMzHzAY",
      "tollbit-domain-verification=0acc441095133f12278c9179168937ecd19b3f5c9b36b930acac5d3a96353c14",
      "smeazeit.sbc1.getdirectrouting.de",
      "mxI8RUm6rfKEWT0c",
      "anthropic-domain-verification-djwjvt=JzQ9OZDYsDipeKOp8ddQCSBkh",
      "mgverify=fa8deab5e1cdad1afca895f77cb4460493457c695b1b6b0bccc40a8732f882da",
      "asv=128b0bc0702196cf36653421800e6808",
      "1password-site-verification=76KQ3OKJ3FH35OMHXYMAINGJ5Q",
      "miro-verification=00f74b9596272eaafb51a7d481892788837e487b",
      "adobe-idp-site-verification=23219eabc0a82ab7eca544a45515b433090e77f559461941395be62189f6d8f0",
      "P2A_58148_200",
      "jamf-site-verification=qlf_TOpLdeS2DNRMndJxIA",
      "5F0-8UN-VT6",
      "elevenlabs=AkVMNw8U-sHd65pGypKEoqiMEsmMhUooL9FJ4TyUgaQ",
      "adobe-idp-site-verification=9204c69a-b8c5-4286-a6d5-6c3259f8cf1d",
      "a8e28041862668f7d799dcf2cdff2f75",
      "teamviewer-sso-verification=0da1e5ee3dc04351aa206dff020cda50",
      "google-site-verification=tLw22x4l0DHcYxy-T7rQxtbQp2bh3_GJ6vAeRXJQEAw",
      "google-gws-recovery-domain-verification=59065683",
      "atlassian-domain-verification=1ImdxQwjaBPB5dXgPBYl2HIs9t45uAqjWHxPe2aKn2aKCTUXGuf3HXbG5vYm2959",
      "pardot1088002=2b9a0e203820f4740ccc144cc3a5c523f49f60334cd030c6b87aac23cf9ef02e",
      "MS=ms15247335",
      "smeazeit.sbc2.getdirectrouting.de",
      "3j98x7j4yjf2xvtw6gt4rt8yjn117l3x",
      "canva-site-verification=HGiDOMp4J0OMWIO_vX2irg",
      "atlassian-domain-verification=0KXQ/HyHlWaW2LeS2kKh/QYjoZkk7smirpVo/Q1IPHetkLFv/eN7OwNE/FKNVMh7",
      "figma-domain-verification=5e6d24ca5cac9fbcdad302605f2185d9a7fef03e17170672f424d334b70a949b-1768473624"
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
    "subject": "commonName=zeit.de",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug  4 05:35:36 2026 GMT",
    "notAfter": "Nov  2 05:35:35 2026 GMT",
    "san": [
      "zeit.de"
    ],
    "days_left": 36,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.40.5.50",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.zeit.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.zeit.de/index"
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
    "klaviyo-site-verification=VfVpZ3",
    "_globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A",
    "apple-domain-verification=TYlrXCrrWPMzHzAY",
    "tollbit-domain-verification=0acc441095133f12278c9179168937ecd19b3f5c9b36b930acac",
    "anthropic-domain-verification-djwjvt=JzQ9OZDYsDipeKOp8ddQCSBkh"
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
      "serial": 603326111351959935795716818064585253019276,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://yr1.c.lencr.org/13.crl"
      ],
      "san": [
        "zeit.de"
      ],
      "subject_dn": "3110300e060355040313077a6569742e6465",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595231",
      "not_before": "20260804053536",
      "not_after": "20261102053535"
    }
  },
  "http2": {
    "robots_disallow": [
      "/angebote/",
      "/zeit/",
      "/suche/",
      "/templates/",
      "/hp_channels/",
      "/send/",
      "/rezepte/suche/",
      "*/comment-thread?",
      "*/liveblog-backend*",
      "/framebuilder/",
      "/campus/framebuilder/",
      "/navigation-teasers*",
      "*iqadcontroller.js",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "50.5.40.34.bc.googleusercontent.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.zeit.de/index",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/apple-app-site-association"
    ],
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
      "urls": 3162,
      "indexes": 3163
    },
    "crl": {
      "url": "http://yr1.c.lencr.org/13.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "x17": {},
  "elapsed_s": 43.4,
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
