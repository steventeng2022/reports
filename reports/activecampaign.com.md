# Security Audit Report — activecampaign.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://activecampaign.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | activecampaign.com |
| Test date | 2026-09-27 02:16 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **28** (High: 0, Medium: 0, Low: 6, Info: 22)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 16 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 17 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 18 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 19 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 20 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 21 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 22 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 23 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 24 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 25 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 26 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 27 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |
| 28 | info | CT1 | 31 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 29 days (notAfter Oct 26 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.1.15:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.1.15:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 16. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): usb. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 17. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 18. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 19. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: ps-cd-verification=445a8aa6-f462-4ac5-89b9-cf62b8f9ea91; ahrefs-site-verification_13f6592c6dbc2e2fd5a07a7ba689ee0acaf5285f7dbf7a1c3eed5fc; google-site-verification=aZc8XNJa2DPnRqQMK58izlsKurjRm-hwdl-U4nsIBjY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 20. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but activecampaign.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 21. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 28 disallow path(s), e.g. /.env, /apps/search/, /blog/archives, /blog/inside-activecampaign, /blog/page
- **Recommendation:** Review disallowed paths; robots is not access control.

### 22. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on activecampaign.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 23. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for activecampaign.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 24. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on activecampaign.com lists 21 <loc> URL(s) across 22 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 25. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of activecampaign.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 26. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of activecampaign.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 27. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of activecampaign.com declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

### 28. [INFO] 31 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: apps.activecampaign.com, assets.activecampaign.com, help.activecampaign.com, status.activecampaign.com, vpn.ad.activecampaign.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "activecampaign.com",
  "dns": {
    "a": [
      "104.20.1.15",
      "104.20.0.15"
    ],
    "aaaa": [
      "2606:4700:10::6814:10f",
      "2606:4700:10::6814:f"
    ],
    "cname": null,
    "mx": [
      "usb-smtp-inbound-2.mimecast.com (pref 10)",
      "usb-smtp-inbound-1.mimecast.com (pref 10)"
    ],
    "ns": [
      "alex.ns.cloudflare.com.",
      "abby.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "ps-cd-verification=445a8aa6-f462-4ac5-89b9-cf62b8f9ea91",
      "ahrefs-site-verification_13f6592c6dbc2e2fd5a07a7ba689ee0acaf5285f7dbf7a1c3eed5fcc8799689a",
      "intacct-esk=4FED1A5177F8769BE0538C06A8C0589E",
      "v=DMARC1; p=none; rua=mailto:dmarc@activecampaign.com",
      "MS=ms78211706",
      "google-site-verification=aZc8XNJa2DPnRqQMK58izlsKurjRm-hwdl-U4nsIBjY",
      "anthropic-domain-verification-2wy46r=746EyPf5UdzlAhUQfRnbJGFAi",
      "google-site-verification=pns8v6xoUCNjHvUFVWiTCI4LJj7LHyz5CPghUG4ZYvc",
      "atlassian-domain-verification=0wCIZBGn1K/9SerwAoj1UyInzqjUZyJTODZJ1UPpBu+swTTfNBZxL2WhQZGvkfo/",
      "docker-verification=88049882-e3b0-454f-bfc6-99f5945ec081",
      "status-page-domain-verification=8wyn9807n4gs",
      "stripe-verification=B8A6127A871981E95923CC0E59815D7C397AD696A04B0E5B60CBE58F81D54B65",
      "apple-domain-verification=VblInNeuuVuHySfU",
      "docusign=b6411fd9-d54c-42ec-9a1e-9c718099b208",
      "openai-domain-verification=dv-hGDc7dQuUtX9y1AaOh3g5zLk",
      "google-site-verification=ZO9kf3bTT021P8qlB2BQ5rmk1e4bS8rsoYTnSpo9Nqg",
      "google-site-verification=5ecE6QK-uN7epMvq2briZD_vYB2nC_5Y3BukiSILBUI",
      "ZOOM_verify_X_DkuppUTyaf0Col_X_dWQ",
      "google-site-verification=z4cu4ksSlD1F4VwsV7aeuI3agrK4xT2HzLJwvNqXh-I",
      "vnr8cy64z7nvm6vq9xycm1t9t3wx625z",
      "cursor-domain-verification-mggxet=yI5H5w8prfWJQbesZn4JgSFiX",
      "v=spf1 ip4:173.236.20.0/24 ip4:192.92.97.0/24 ip4:52.128.40.0/21 ip4:217.8.118.0/24 ip4:103.229.233.0/24 include:usb._netblocks.mimecast.com include:_spf.google.com include:mail.zendesk.com include:stspg-customer.com include:sent-via.netsuite.com include:",
      "_spf-",
      "lrn.activecampaign.com ~all",
      "google-site-verification=bsPOFNz4WrydBvfNkWbSIfsIlkRev4iGBxCHnB3wsA4",
      "cloudflare_dashboard_sso=68e80b6640cd17c492819fa073f4c765",
      "google-site-verification=hLQ1bCw_QcM04p9JX8V-EF2yFMN1phpFf4F1XAYSkXg",
      "google-site-verification=yZpqL2DYnFgeE1CANvNSvCaY6vchX6cUsOnKIswM9nY",
      "google-site-verification=oZuy90wJc1WtJL-OqSxrqLKcqE_xWlBcRncm88kc6xo",
      "pendo-domain-verification=JK5zYujOmKqXb5aS1pRudbgHp2s",
      "canva-site-verification=jr7ubLUf4AdQz7NWkCAPnQ",
      "asv=2a7893285fd0ab817b0ac10ee4afcded",
      "facebook-domain-verification=vj4bbc79ppnrt612769n33gxnqezjt"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:re+eab9f0889f10@inbound.dmarcdigests.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "jurisdictionCountryName=US, jurisdictionStateOrProvinceName=Delaware, businessCategory=Private Organization, serialNumber=5943439, countryName=US, stateOrProvinceName=Illinois, localityName=Chicago, organizationName=ActiveCampaign, LLC, commonName=www.activecampaign.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=GeoTrust EV RSA CA G2",
    "notBefore": "Sep 25 00:00:00 2025 GMT",
    "notAfter": "Oct 26 23:59:59 2026 GMT",
    "san": [
      "www.activecampaign.com",
      "activecampaign.com"
    ],
    "days_left": 29,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.20.1.15",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "activecampaign.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.activecampaign.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.activecampaign.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 31,
    "notable": [
      "apps.activecampaign.com",
      "assets.activecampaign.com",
      "help.activecampaign.com",
      "status.activecampaign.com",
      "vpn.ad.activecampaign.com"
    ],
    "sample": [
      "acideas.activecampaign.com",
      "activecampaign.com",
      "activelyblack.activecampaign.com",
      "ap.activecampaign.com",
      "apps.activecampaign.com",
      "assets.activecampaign.com",
      "autonomous.activecampaign.com",
      "community.activecampaign.com",
      "community2.activecampaign.com",
      "cwv.activecampaign.com",
      "developers.activecampaign.com",
      "events.activecampaign.com",
      "go.activecampaign.com",
      "gtm.activecampaign.com",
      "help.activecampaign.com",
      "ideas.activecampaign.com",
      "issues.activecampaign.com",
      "leapday.activecampaign.com",
      "leapday2024.activecampaign.com",
      "myacstory.activecampaign.com"
    ]
  },
  "apex_txt": [
    "ps-cd-verification=445a8aa6-f462-4ac5-89b9-cf62b8f9ea91",
    "ahrefs-site-verification_13f6592c6dbc2e2fd5a07a7ba689ee0acaf5285f7dbf7a1c3eed5fc",
    "google-site-verification=aZc8XNJa2DPnRqQMK58izlsKurjRm-hwdl-U4nsIBjY",
    "anthropic-domain-verification-2wy46r=746EyPf5UdzlAhUQfRnbJGFAi",
    "google-site-verification=pns8v6xoUCNjHvUFVWiTCI4LJj7LHyz5CPghUG4ZYvc"
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
      "serial": 10665879359626515853142343286034070450,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/GeoTrustEVRSACAG2.crl",
        "http://crl4.digicert.com/GeoTrustEVRSACAG2.crl"
      ],
      "san": [
        "www.activecampaign.com",
        "activecampaign.com"
      ],
      "subject_dn": "31133011060b2b0601040182373c0201031302555331193017060b2b0601040182373c020102130844656c6177617265311d301b060355040f0c1450726976617465204f7267616e697a6174696f6e3110300e0603550405130735393433343339310b30090603550406130255533111300f06035504081308496c6c696e6f69733110300e060355040713074368696361676f311c301a060355040a131341637469766543616d706169676e2c204c4c43311f301d060355040313167777772e61637469766563616d706169676e2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63311e301c0603550403131547656f547275737420455620525341204341204732",
      "not_before": "20250925000000",
      "not_after": "20261026235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/.env",
      "/apps/search/",
      "/blog/archives",
      "/blog/inside-activecampaign",
      "/blog/page",
      "/blog/tag",
      "/c/",
      "/cache/",
      "/comment-page-1",
      "/cpresources/",
      "/elementor-*",
      "/l/",
      "/learn/category/",
      "/learn/tag/",
      "/podcast/feed"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.activecampaign.com/",
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
    "hsts": "max-age=63072000; includeSubDomains; preload",
    "sitemap": {
      "urls": 21,
      "indexes": 22
    },
    "crl": {
      "url": "http://crl3.digicert.com/GeoTrustEVRSACAG2.crl",
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
    "alt_svc": "h3=\":443\"; ma=86400"
  },
  "x17": {
    "ocsp_http": "http://ocsp.digicert.com"
  },
  "elapsed_s": 10.6,
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
