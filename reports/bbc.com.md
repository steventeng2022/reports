# Security Audit Report — bbc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bbc.com/ |
| Bug bounty program | BBC |
| Listed scope domain | bbc.com |
| Test date | 2026-09-27 01:11 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 4, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
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
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 17 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 18 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 19 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 20 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 21 | info | CT1 | 89 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: Varnish
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
- **Detail:** Apex TXT records with verification/token content: jamf-site-verification=28Mn3O6rTBSXkL5w6c911A; airtable-verification=b1a394c872dd6721d39a1d91cc96080d; Validity-Domain-Verification=TYXJnAeGHNF4DGlOgE4vdoDT3a0=
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 88 disallow path(s), e.g. /asset/, /backstage/bbc-login-help/, /backstage/bbc-login-help$, /bitesize/search$, /bitesize/search/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://bbc.com/ carries Cache-Control: public,max-age=604800,stale-while-revalidate=3600,stale-if-error=3600; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 17. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on bbc.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of bbc.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 18. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on bbc.com lists 5 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 19. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of bbc.com carries alt-svc h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 20. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on bbc.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 21. [INFO] 89 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: account-api.api.bbc.com, activity.api.bbc.com, activity.int.api.bbc.com, activity.stage.api.bbc.com, activity.test.api.bbc.com, af-dummy-ui-1.test.api.bbc.com, amservice.api.bbc.com, amservice.int.api.bbc.com, amservice.stage.api.bbc.com, amservice.test.api.bbc.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "bbc.com",
  "dns": {
    "a": [
      "151.101.192.81",
      "151.101.128.81",
      "151.101.64.81",
      "151.101.0.81"
    ],
    "aaaa": [
      "2a04:4e42::81",
      "2a04:4e42:200::81",
      "2a04:4e42:600::81",
      "2a04:4e42:400::81"
    ],
    "cname": null,
    "mx": [
      "cluster8a.eu.messagelabs.com (pref 20)",
      "cluster8.eu.messagelabs.com (pref 10)"
    ],
    "ns": [
      "dns1.bbc.co.uk.",
      "dns0.bbc.com.",
      "ddns0.bbc.co.uk.",
      "ddns1.bbc.co.uk.",
      "ddns1.bbc.com.",
      "dns0.bbc.co.uk.",
      "ddns0.bbc.com.",
      "dns1.bbc.com."
    ],
    "caa": [
      "0 iodef \"mailto:security@bbc.co.uk\"",
      "0 issue \"amazon.com\"",
      "0 issuewild \"globalsign.com\"",
      "0 issue \"globalsign.com\"",
      "0 issue \"digicert.com\""
    ],
    "spf": [
      "docusign=57499c1f-9099-463b-a5bd-cb7583816d78",
      "jamf-site-verification=28Mn3O6rTBSXkL5w6c911A",
      "airtable-verification=b1a394c872dd6721d39a1d91cc96080d",
      "Validity-Domain-Verification=TYXJnAeGHNF4DGlOgE4vdoDT3a0=",
      "atlassian-sending-domain-verification=da3721b6-1d2c-4c32-bf01-b792667aeb4d",
      "google-site-verification=mTy-FoNnG0yetpI3-0e9AXctAkUCcWGc_K3BcMfioFI",
      "adobe-idp-site-verification=c3a16fcb00ac5365e4ea125d5e59d4be11936f768b3020c4d81b4232019604a2",
      "_globalsign-domain-verification=PpIYEptb1-AaatNRPoS2XiWRmxR7zAT1MR52dvDNzx",
      "docusign=75217687-3ba0-49bb-bb3b-482d888493af",
      "docker-verification=f89691bb-7bdd-4bc1-9673-57454d6d9c42",
      "v=spf1 ip4:212.58.224.0/19 ip4:132.185.0.0/16 +include:spf.messagelabs.com ~all",
      "xoCARoExwkNhLPdKaaxv",
      "atlassian-domain-verification=SQsgJ5h/FqwMTXuSG/G4Nd1Gx6uX2keREOsZSa22D5XT46EsEuyaic8Aej4cR4Tr",
      "dropbox-domain-verification=mtgv0f2pudoz",
      "slack-domain-verification=hza4gfkmctQ7A7BpMhGNVOZVZcKTFC8OC5ewDFVA"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;aspf=s;adkim=s;pct=100;fo=0;ri=86400; rua=mailto:dmarc_agg@vali.email;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=GB, stateOrProvinceName=London, localityName=London, organizationName=BRITISH BROADCASTING CORPORATION, commonName=www.bbc.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R46 OV TLS CA 2025",
    "notBefore": "Aug 21 11:32:02 2026 GMT",
    "notAfter": "Jan 24 05:46:23 2027 GMT",
    "san": [
      "www.bbc.com",
      "account.bbc.com",
      "session.bbc.com",
      "account.bbc.co.uk",
      "bbc.co.uk",
      "bbcrussian.com",
      "cdnedge.bbc.co.uk",
      "news.bbc.co.uk",
      "news.bbcimg.co.uk",
      "newsimg.bbc.co.uk",
      "newsrss.bbc.co.uk",
      "newsvote.bbc.co.uk",
      "node1.bbcimg.co.uk",
      "open.live.bbc.co.uk",
      "playlists.bbc.co.uk",
      "r.bbci.co.uk",
      "search.bbc.co.uk",
      "session.bbc.co.uk",
      "www.bbc.co.uk",
      "www.bbcrussian.com",
      "wwwnews.live.bbc.co.uk",
      "bbc.com"
    ],
    "days_left": 119,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.192.81",
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
      "origin": "https://sub.bbc.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bbc.com/"
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
    "count": 89,
    "notable": [
      "account-api.api.bbc.com",
      "activity.api.bbc.com",
      "activity.int.api.bbc.com",
      "activity.stage.api.bbc.com",
      "activity.test.api.bbc.com",
      "af-dummy-ui-1.test.api.bbc.com",
      "amservice.api.bbc.com",
      "amservice.int.api.bbc.com",
      "amservice.stage.api.bbc.com",
      "amservice.test.api.bbc.com",
      "api.int.bbcx.test.api.bbc.com",
      "api.stage.bbcx.test.api.bbc.com",
      "api.test.bbcx.test.api.bbc.com",
      "audco.api.bbc.com",
      "audco.int.api.bbc.com"
    ],
    "sample": [
      "account-api.api.bbc.com",
      "activity.api.bbc.com",
      "activity.int.api.bbc.com",
      "activity.stage.api.bbc.com",
      "activity.test.api.bbc.com",
      "af-dummy-ui-1.test.api.bbc.com",
      "amservice.api.bbc.com",
      "amservice.int.api.bbc.com",
      "amservice.stage.api.bbc.com",
      "amservice.test.api.bbc.com",
      "api.int.bbcx.test.api.bbc.com",
      "api.stage.bbcx.test.api.bbc.com",
      "api.test.bbcx.test.api.bbc.com",
      "audco.api.bbc.com",
      "audco.int.api.bbc.com",
      "audco.stage.api.bbc.com",
      "audco.test.api.bbc.com",
      "bag.int.api.bbc.com",
      "bag.stage.api.bbc.com",
      "bag.test.api.bbc.com"
    ]
  },
  "apex_txt": [
    "jamf-site-verification=28Mn3O6rTBSXkL5w6c911A",
    "airtable-verification=b1a394c872dd6721d39a1d91cc96080d",
    "Validity-Domain-Verification=TYXJnAeGHNF4DGlOgE4vdoDT3a0=",
    "atlassian-sending-domain-verification=da3721b6-1d2c-4c32-bf01-b792667aeb4d",
    "google-site-verification=mTy-FoNnG0yetpI3-0e9AXctAkUCcWGc_K3BcMfioFI"
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
      "aia_ocsp": "http://ocsp.globalsign.com/gsgccr46ovtlsca2025",
      "serial": 34190963914933566318619885744,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.globalsign.com/gsgccr46ovtlsca2025.crl"
      ],
      "subject_dn": "310b3009060355040613024742310f300d060355040813064c6f6e646f6e310f300d060355040713064c6f6e646f6e31293027060355040a1320425249544953482042524f414443415354494e4720434f52504f524154494f4e311430120603550403130b7777772e6262632e636f6d",
      "issuer_dn": "310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312a302806035504031321476c6f62616c5369676e2047434320523436204f5620544c532043412032303235",
      "not_before": "20260821113202",
      "not_after": "20270124054623"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/asset/",
      "/backstage/bbc-login-help/",
      "/backstage/bbc-login-help$",
      "/bitesize/search$",
      "/bitesize/search/",
      "/bitesize/search?",
      "/cbbc/search/",
      "/cbbc/search$",
      "/cbbc/search?",
      "/cbeebies/search/",
      "/cbeebies/search$",
      "/cbeebies/search?",
      "/chwilio/",
      "/chwilio$",
      "/chwilio?"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.bbc.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000; preload",
    "sitemap": {
      "urls": 5,
      "indexes": 0
    },
    "crl": {
      "url": "http://crl.globalsign.com/gsgccr46ovtlsca2025.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "alt_svc": "h3=\":443\";ma=86400,h3-29=\":443\";ma=86400,h3-27=\":443\";ma=86400",
    "cdn": [
      "Fastly"
    ]
  },
  "elapsed_s": 17.7,
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
