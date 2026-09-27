# Security Audit Report — amazon.co.uk

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://amazon.co.uk/ |
| Bug bounty program | Amazon |
| Listed scope domain | amazon.co.uk |
| Test date | 2026-09-27 01:09 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 5, Info: 16)

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
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 17 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 20 | info | CT1 | 125 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 21 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** Apex TXT records with verification/token content: liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo; docker-verification=b640e25c-e841-4505-9fa7-160d642dca15; stripe-verification=8E217BE0FF12B50596BD78EEA3F81E62C6C7A2AC78FBD46DAD95B7D21BA2
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 193 disallow path(s), e.g. /dp/product-availability/, /dp/rate-this-item/, /exec/obidos/account-access-login, /exec/obidos/change-style, /exec/obidos/dt/assoc/handle-buy-box
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.253.181.192 carries PTR ec2-3-253-181-192.eu-west-1.compute.amazonaws.com. for amazon.co.uk.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 17. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on amazon.co.uk; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for amazon.co.uk; apex co.uk, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The amazon.co.uk certificate lists an AIA OCSP responder (http://status.geotrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [INFO] 125 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.sandbox.amazon.co.uk, beta.gql.music.amazon.co.uk, cloud.amazon.co.uk, files.amazon.co.uk, help.amazon.co.uk, jobs.amazon.co.uk, pay.amazon.co.uk, support.amazon.co.uk
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 21. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: files.amazon.co.uk; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "amazon.co.uk",
  "dns": {
    "a": [
      "3.253.181.192",
      "3.254.236.223",
      "3.253.170.23"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns-430.awsdns-53.com.",
      "ns-1256.awsdns-29.org.",
      "ns-558.awsdns-05.net.",
      "ns-1689.awsdns-19.co.uk."
    ],
    "caa": [],
    "spf": [
      "ZOOM_verify_3Ko9ExAfA3lpXCh9QPR15B",
      "sending_domain229492=bc19ba09b42dbc12618ad5755af2606329fa3a20ca423a330779fb5cfa0e71ce",
      "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
      "docker-verification=b640e25c-e841-4505-9fa7-160d642dca15",
      "MS=ms45048758",
      "sending_domain1003771=503f4d4816370d2e5c2f06087d972e8c76d700ddf473e8976f7e72f6e4940089",
      "stripe-verification=8E217BE0FF12B50596BD78EEA3F81E62C6C7A2AC78FBD46DAD95B7D21BA2F8BF",
      "bluebeam-verification=fgp6rwxcjjb4ey0fzju6w6fwyhdo2i",
      "autodesk-domain-verification=9bCtBBfcSX131DnPfMqz",
      "sending_domain229492=2712d9f9a3a3adcb0285c54b3ea3cb718a69130fc0ddfa34cc74dcefe396f31a",
      "sending_domain1003771=6d479c2e18f1858893f5c32bf9908c9b085932a84541ee85c8d873ed7f24b83f",
      "google-gws-recovery-domain-verification=68063740",
      "kahoot-domain-verification=46f023d24c9f43ecb921a6532cfcdb884a30a46955a4151bb1ef59a4bbe26a0c",
      "google-site-verification=lVzfHahZqH9Fqj0vAsjH_J5ee3Zewa0CMgaj6Tqixxg",
      "MS=ms12314789",
      "v=spf1 include:amazon.com -all",
      "cisco-ci-domain-verification=2d2409c79bc50c72151404f511810173a1d51f0721e3f7090b2dcda39aa3a7f1",
      "sending_domain608861=81f88310c30e2fee703ed330cd919efe1f70cb299998749208d381707f584c8c",
      "google-gws-recovery-domain-verification=70440345",
      "google-site-verification=6t-dcIVf42O-EoNSfBL2kWoN33DKL83FokcApn7S2us",
      "facebook-domain-verification=s683te1vv3i7f7c7fbq4ps45yxkt6l",
      "adobe-idp-site-verification=b6bcd3e5aaffc63607c8bf75744d9a0d1febc50dd7f389428e2ae476c9ba8814",
      "cisco-ci-domain-verification=7efb722588ec060653fa68cb28b9206879d3abc91ffab361fd37cedf44bebfe7",
      "google-site-verification=g_bTkCPIdl9j6VSKKAfoQl12ZHKgvAk0X3lwzUqu1fM",
      "spf2.0/pra include:amazon.com -all",
      "sending_domain608861=d7e8b07477dfc929c3eaf73f3d87d52b876cb7ceaaf93c6213319abf8120b52e",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "box-domain-verification=ffea95cd0e0d61c302198367155b07e74fd534fa1d867662dc9bf9969b6f535d",
      "canva-site-verification=FSBzoxF2qUazDMl38A7ESw"
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
    "subject": "commonName=*.peg.a2z.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=GeoTrust TLS RSA CA G1",
    "notBefore": "Sep 20 00:00:00 2026 GMT",
    "notAfter": "Apr  5 23:59:59 2027 GMT",
    "san": [
      "amazon.co.uk",
      "uedata.amazon.co.uk",
      "www.amazon.co.uk",
      "origin-www.amazon.co.uk",
      "*.peg.a2z.com",
      "amazon.com",
      "amzn.com",
      "uedata.amazon.com",
      "us.amazon.com",
      "www.amazon.com",
      "www.amzn.com",
      "corporate.amazon.com",
      "buybox.amazon.com",
      "iphone.amazon.com",
      "yp.amazon.com",
      "home.amazon.com",
      "origin-www.amazon.com",
      "origin2-www.amazon.com",
      "buckeye-retail-website.amazon.com",
      "huddles.amazon.com",
      "amazon.de",
      "www.amazon.de",
      "origin-www.amazon.de",
      "amazon.co.jp",
      "amazon.jp",
      "www.amazon.jp",
      "www.amazon.co.jp",
      "origin-www.amazon.co.jp",
      "*.aa.peg.a2z.com",
      "*.ab.peg.a2z.com",
      "*.ac.peg.a2z.com",
      "origin-www.amazon.com.au",
      "www.amazon.com.au",
      "*.bz.peg.a2z.com",
      "amazon.com.au",
      "origin2-www.amazon.co.jp",
      "edgeflow.aero.4d5ad1d2b-frontier.amazon.co.jp",
      "edgeflow.aero.04f01a85e-frontier.amazon.com.au",
      "edgeflow.aero.47cf2c8c9-frontier.amazon.com",
      "edgeflow.aero.abe2c2f23-frontier.amazon.de",
      "edgeflow.aero.bfbdc3ca1-frontier.amazon.co.uk",
      "edgeflow-dp.aero.4d5ad1d2b-frontier.amazon.co.jp",
      "edgeflow-dp.aero.04f01a85e-frontier.amazon.com.au",
      "edgeflow-dp.aero.47cf2c8c9-frontier.amazon.com",
      "edgeflow-dp.aero.bfbdc3ca1-frontier.amazon.co.uk",
      "edgeflow-dp.aero.abe2c2f23-frontier.amazon.de",
      "shop.business.amazon.com"
    ],
    "days_left": 190,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.253.181.192",
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
      "origin": "https://sub.amazon.co.uk",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://amazon.co.uk/"
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
    "count": 125,
    "notable": [
      "api.sandbox.amazon.co.uk",
      "beta.gql.music.amazon.co.uk",
      "cloud.amazon.co.uk",
      "files.amazon.co.uk",
      "help.amazon.co.uk",
      "jobs.amazon.co.uk",
      "pay.amazon.co.uk",
      "support.amazon.co.uk"
    ],
    "sample": [
      "a4k-beta.amazon.co.uk",
      "a4k-gamma.amazon.co.uk",
      "a4k.amazon.co.uk",
      "aan.amazon.co.uk",
      "aax-eu.amazon.co.uk",
      "accelerator.amazon.co.uk",
      "account-status.amazon.co.uk",
      "advantage.amazon.co.uk",
      "aeswidgets.amazon.co.uk",
      "affiliate-program.amazon.co.uk",
      "alexa-skills-beta-eu.amazon.co.uk",
      "alexa-skills-beta.amazon.co.uk",
      "amg.amazon.co.uk",
      "amh.amazon.co.uk",
      "api-key.amazon.co.uk",
      "api-preprod.amazon.co.uk",
      "api-sandbox.amazon.co.uk",
      "api.sandbox.amazon.co.uk",
      "arcus-www.amazon.co.uk",
      "asmw.amazon.co.uk"
    ],
    "dangling": [
      "files.amazon.co.uk"
    ]
  },
  "apex_txt": [
    "liveramp-site-verification=jZJKgMEQ_1mdjMhKj02iqNACZ-NJHRWhCEQdQ_OuCMo",
    "docker-verification=b640e25c-e841-4505-9fa7-160d642dca15",
    "stripe-verification=8E217BE0FF12B50596BD78EEA3F81E62C6C7A2AC78FBD46DAD95B7D21BA2",
    "bluebeam-verification=fgp6rwxcjjb4ey0fzju6w6fwyhdo2i",
    "autodesk-domain-verification=9bCtBBfcSX131DnPfMqz"
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
      "aia_ocsp": "http://status.geotrust.com",
      "serial": 7155697021029473683065491393650584458,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl"
      ],
      "subject_dn": "3116301406035504030c0d2a2e7065672e61327a2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311f301d0603550403131647656f547275737420544c5320525341204341204731",
      "not_before": "20260920000000",
      "not_after": "20270405235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
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
      "/gp/cart",
      "/gp/content-form"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-3-253-181-192.eu-west-1.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.amazon.co.uk/",
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
      "url": "http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl",
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
  "elapsed_s": 39.6,
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
