# Security Audit Report — newegg.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://newegg.com/ |
| Bug bounty program | Newegg |
| Listed scope domain | newegg.com |
| Test date | 2026-09-27 01:28 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 3, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
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
- **Detail:** Apex TXT records with verification/token content: cursor-domain-verification-w61mwq=TQrKtOakRs3OBorucA3sDlbEQ; anthropic-domain-verification-1k1kwv=sA28xQK50TxxHO9tIaJbCEP60; apple-domain-verification=fookR9-T71Tb7G4opXgos6kiHa32YIsCriQxJY4SNU8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.digicert.com -> http-200
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but newegg.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 86 disallow path(s), e.g. /Common/BML/, /Common/ThirdParty/, /App/, /Application/, /Configuration/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 104.115.226.136 carries PTR a104-115-226-136.deploy.static.akamaitechnologies.com. for newegg.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "newegg.com",
  "dns": {
    "a": [
      "104.115.226.136"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-004ed001.gslb.pphosted.com (pref 10)",
      "mxa-004ed001.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns0011.secondary.cloudflare.com.",
      "a16-66.akam.net.",
      "a24-67.akam.net.",
      "a7-65.akam.net.",
      "a28-64.akam.net.",
      "a1-21.akam.net.",
      "ns0197.secondary.cloudflare.com.",
      "a9-66.akam.net."
    ],
    "caa": [
      "0 issue \"pki.goog\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"digicert.com\"",
      "0 issue \"amazon.com\"",
      "0 issue \"sectigo.com\""
    ],
    "spf": [
      "cursor-domain-verification-w61mwq=TQrKtOakRs3OBorucA3sDlbEQ",
      "v=spf1 ip4:107.20.210.250/32 ip4:52.1.14.157/32 ip4:216.52.208.0/24 ip4:204.14.213.0/24 ip4:204.89.152.0/24 ip4:50.79.138.221 include:spf-004ed001.pphosted.com include:u1970239.wl.sendgrid.net include:spf.protection.outlook.com -all",
      "_a4kh6j7awcaw7fxqj5shnpuurxqqwy8",
      "ca3-d55519625ba84c9aa83e9e9a416063ba",
      "anthropic-domain-verification-1k1kwv=sA28xQK50TxxHO9tIaJbCEP60",
      "apple-domain-verification=fookR9-T71Tb7G4opXgos6kiHa32YIsCriQxJY4SNU8",
      "yahoo-verification-key=UuN8VB7V7E4fK9e6tGDxdS2LNdDFfDU50tLmkOQftws=",
      "google-site-verification=ajXtDle0UfsPUgtjCZ37T8opwg2zvXLzkHNjZTlIVFI"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@newegg.com; ruf=mailto:dmarcruf@newegg.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=Indiana, localityName=Indianapolis, organizationName=INOPC Inc., commonName=www.usopc.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Apr 29 00:00:00 2026 GMT",
    "notAfter": "Nov 13 23:59:59 2026 GMT",
    "san": [
      "www.usopc.com",
      "c1.neweggimages.com",
      "c2.neweggimages.com",
      "carriercentral.newegg.com",
      "chat.newegg.com",
      "download.newegg.com",
      "eniac.newegg.com",
      "esuohni.onewegg.com",
      "flash.newegg.com",
      "globalselling.newegg.com",
      "help.newegg.ca",
      "help.newegg.com",
      "help.neweggbusiness.com",
      "ih.newegg.com",
      "images10.newegg.com",
      "images10.nutrend.com",
      "images10.rosewill.com",
      "imgion4.newegg.com",
      "imk.neweggimages.com",
      "investors.newegg.com",
      "kb.newegg.ca",
      "kb.newegg.com",
      "kb.neweggbusiness.com",
      "newegg.ca",
      "newegg.com",
      "neweggbusiness.com",
      "nuget.newegg.com",
      "ows1.newegg.com",
      "partner.newegg.com",
      "pf.newegg.com",
      "pmtcards.newegg.com",
      "promotions.newegg.ca",
      "promotions.newegg.com",
      "promotions.neweggbusiness.com",
      "promotions.nutrend.com",
      "push.newegg.com",
      "secure.m.newegg.ca",
      "secure.m.newegg.com",
      "secure.newegg.ca",
      "secure.newegg.com",
      "secure.neweggbusiness.com",
      "sellingpilot.newegg.com",
      "ssl-images.newegg.com",
      "staffing.newegg.com",
      "usopc.com",
      "waf-poc.newegg.com",
      "www-ts1.newegg.com",
      "www-ts2.newegg.com",
      "www.newegg.ca",
      "www.newegg.com",
      "www.neweggbusiness.com",
      "www.neweggstaffing.com",
      "www.rosewill.com",
      "www.rosewillhome.com",
      "www2.newegg.com"
    ],
    "days_left": 47,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.115.226.136",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.newegg.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.newegg.com/"
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
    "cursor-domain-verification-w61mwq=TQrKtOakRs3OBorucA3sDlbEQ",
    "anthropic-domain-verification-1k1kwv=sA28xQK50TxxHO9tIaJbCEP60",
    "apple-domain-verification=fookR9-T71Tb7G4opXgos6kiHa32YIsCriQxJY4SNU8",
    "yahoo-verification-key=UuN8VB7V7E4fK9e6tGDxdS2LNdDFfDU50tLmkOQftws=",
    "google-site-verification=ajXtDle0UfsPUgtjCZ37T8opwg2zvXLzkHNjZTlIVFI"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 19204725383256575660251562337711215554,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
        "http://crl4.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl"
      ],
      "subject_dn": "310b30090603550406130255533110300e06035504081307496e6469616e61311530130603550407130c496e6469616e61706f6c697331133011060355040a130a494e4f504320496e632e311630140603550403130d7777772e75736f70632e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473320544c532045434320534841333834203230323020434131",
      "not_before": "20260429000000",
      "not_after": "20261113235959"
    },
    "ocsp": "http-200"
  },
  "http2": {
    "robots_disallow": [
      "/Common/BML/",
      "/Common/ThirdParty/",
      "/App/",
      "/Application/",
      "/Configuration/",
      "/NewMyAccount/",
      "/MyNewegg/",
      "/insider/blog/wp-admin/",
      "/api/UpdateStorage",
      "/api/TrendingNow",
      "/mycountry",
      "/api/MiniCart",
      "/api/GetStorage",
      "/areyouahuman",
      "/api/Common/GBuy"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "a104-115-226-136.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.newegg.com/",
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
    "hsts": "max-age=31536000; includeSubDomains",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
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
  "elapsed_s": 23.3,
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
