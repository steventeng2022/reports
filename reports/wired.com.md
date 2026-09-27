# Security Audit Report — wired.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wired.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | wired.com |
| Test date | 2026-09-27 01:37 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

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
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 20 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
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
- **Detail:** Header reveals: nginx
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
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=mYtQWl3namqmk5ikMKT48XVnS+XdjdbkLlkWMcNyvsddK2JDAi; zapier-domain-verification-challenge=97705597-a31c-4c6d-aa76-7e01d2b3fe13; google-site-verification=h3oXJvoyRaANoWJ-cjd8H3Zv49YViS96em2ZhNfeGPo
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 14 disallow path(s), e.g. /*?, /auth/, /account/, /user/, /user-context
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 166.117.251.134 carries PTR aeed6796a0f5c0317.awsglobalaccelerator.com. for wired.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for wired.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The wired.com certificate lists an AIA OCSP responder (http://ocsp.r2m04.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on wired.com lists 60 <loc> URL(s) across 61 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "wired.com",
  "dns": {
    "a": [
      "166.117.251.134",
      "52.223.6.210"
    ],
    "aaaa": [
      "2600:9000:a41b:ef95:eff:32b3:411c:f36c",
      "2600:9000:a707:a46c:560f:b721:9702:d75e"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-836.awsdns-40.net.",
      "ns-1935.awsdns-49.co.uk.",
      "ns-1116.awsdns-11.org.",
      "ns-28.awsdns-03.com."
    ],
    "caa": [],
    "spf": [
      "atlassian-domain-verification=mYtQWl3namqmk5ikMKT48XVnS+XdjdbkLlkWMcNyvsddK2JDAib+9a8MJCXTDMyJ",
      "ZOOM_verify_PeuZagN7TzybBaD-uxsGAw",
      "zapier-domain-verification-challenge=97705597-a31c-4c6d-aa76-7e01d2b3fe13",
      "google-site-verification=h3oXJvoyRaANoWJ-cjd8H3Zv49YViS96em2ZhNfeGPo",
      "loaderio=b8d2a4d94bf4574bd8c95427c0fcbee6",
      "907D-6CE2-7BD0-FF0C-7E83-E21D-AD2B-DD27",
      "globalsign-domain-verification=Wq9iztGUzQcBBi1OLrEOlXtefwOzX7yfvhbsw-CVdo",
      "v=spf1 include:_u.wired.com._spf.smart.ondmarc.com ~all",
      "airalo-domain-verification=8o95GSpImu3dWoe",
      "_globalsign-domain-verification=ln6G6qMbrMeJLZSOGjjxis2fcs9NHicunfT-JK_mCZ",
      "3c5bnsm2366rtqny77w8cq9wvy49r0w9",
      "MS=ms43391860",
      "docusign=093f2a18-6882-43f7-a9ae-b2594de9d47f",
      "google-site-verification=Njx9q6Atd2al1mD6wtXu2u83s0Sz6WZQa_r0jmg261k",
      "google-site-verification=39CB9sd7tH1nrsJcVjjUzO9sVoKZ-2MBshlRhqFX13k",
      "yahoo-verification-key=HFoI8YeAFA0EIy9UkTckoOvVblp1gSUBZM9B8KKeYNs=",
      "fastly-domain-delegation-grdt7uboiyaqqtgjenzi-789661-2024-07-19",
      "fastly-domain-delegation-duxxxum9cshse9phbfst-554686-2022-12-12",
      "google-site-verification=8dMUQRGxbDNDoEIZXU-E4-GmKLNvgkFwwAmqY0qUroU",
      "_globalsign-domain-verification=5gwbTrtjX4CPebqVSR8L6SpOvnf_3_6K7X0z_Izh9q",
      "anthropic-domain-verification-qjhty4=rH0iOGSnUm12xzxooo18gnz9G",
      "MS=ms32964175",
      "_globalsign-domain-verification=GXpUUS49HB9rYWZEmxJFtZdS61weLMlf91w9Dn-5O0",
      "openai-domain-verification=dv-LCvTXCMns2J5grLiXF1uTD2T",
      "facebook-domain-verification=75aqj8blnqc3dj5cy9b5d9mialys78",
      "google-site-verification=tA0Sx_MrXe58GUfjaTg-EgrfF7wv1WdDVKKq7dyNuwc",
      "figma-domain-verification=2edc90f8e8740d757633998df93b92af5494d0ad60e746b5a5a252e8b62d7361-1786438367",
      "adobe-idp-site-verification=c2108b9dbc0fc05ff0794006df1c41b6c945bd2c8a904bef754ec850a7c6873f"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:a6816915@inbox.ondmarc.com; ruf=mailto:a6816915@inbox.ondmarc.com; adkim=r; aspf=r; fo=1; rf=afrf; ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.worldofinteriors.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Oct 23 00:00:00 2025 GMT",
    "notAfter": "Nov 21 23:59:59 2026 GMT",
    "san": [
      "*.worldofinteriors.com",
      "condenast.de",
      "cnworld.es",
      "gqheroes.com",
      "wired.uk",
      "condenastdigital.com",
      "pitchfork.com",
      "cnidigital.in",
      "worldofinteriors.co.uk",
      "condenastcollege.es",
      "gq.co.uk",
      "teenvogue.com",
      "condenast.co.uk",
      "worldofinteriors.com",
      "vanityfairart.co.uk",
      "gq-magazine.co.uk",
      "vogue.de",
      "gqeditorsclub.co.uk",
      "architecturaldigest.com.mx",
      "revistaad.es",
      "traveller.uk",
      "vogue.com.mx",
      "wired.it",
      "glmr.uk",
      "houseandgarden.com",
      "theexchangehsbc.com",
      "condenast.com.tw",
      "glamourmagazine.co.uk",
      "ouse.co",
      "glamour.com.mx",
      "*.worldofinteriors.uk",
      "pitchforkmusicfestival.com",
      "allure.com",
      "newyorker.com",
      "self.com",
      "vogue.uk",
      "arstechnica.uk",
      "glamour.de",
      "houseandgarden.co.uk",
      "admiddleeast.com",
      "menoftheyear.de",
      "wired.com",
      "cntraveler.com",
      "tatler.com",
      "tatler.co.uk",
      "worldofinteriors.uk",
      "condenast.com.mx",
      "condenast.fr",
      "vogue.mx",
      "vogue.it",
      "gqheroes.co.uk",
      "them.us",
      "cntraveller.com",
      "arstechnica.co.uk",
      "vogue.es",
      "vanityfair.co.uk",
      "voguesummerschool.com",
      "vanityfair.com",
      "cntraveiier.com",
      "tatler.uk",
      "gq.uk",
      "condenast.jp",
      "condenastcollege.ac.uk",
      "calicoclub.co.uk",
      "glamour.com",
      "cntraveller.in",
      "vogue.co.jp",
      "condenast.mx",
      "condenast.it",
      "condenastjohansensguides.com",
      "gqeditorsclub.com",
      "gq.de",
      "vogue.fr",
      "cntraveller.uk",
      "condenast.es",
      "admexico.com.mx",
      "vogueforcesoffashion.com",
      "condenast.in",
      "vogue.co.uk",
      "thelovemagazine.co.uk",
      "vanityfairart.com",
      "condenastjohansens.com",
      "gq.com",
      "vogue.com",
      "condenastcollege.com",
      "architecturaldigest.com",
      "cntravellerme.com",
      "cntravelller.com",
      "bonappetit.com",
      "wired.co.uk",
      "condenastdigital.de",
      "condenastmexico-latam.com"
    ],
    "days_left": 55,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "166.117.251.134",
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
      "origin": "https://sub.wired.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.wired.com/"
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
    "/.env": 403,
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
    "atlassian-domain-verification=mYtQWl3namqmk5ikMKT48XVnS+XdjdbkLlkWMcNyvsddK2JDAi",
    "zapier-domain-verification-challenge=97705597-a31c-4c6d-aa76-7e01d2b3fe13",
    "google-site-verification=h3oXJvoyRaANoWJ-cjd8H3Zv49YViS96em2ZhNfeGPo",
    "globalsign-domain-verification=Wq9iztGUzQcBBi1OLrEOlXtefwOzX7yfvhbsw-CVdo",
    "airalo-domain-verification=8o95GSpImu3dWoe"
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
      "serial": 5361486114573623908439960265293471579,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "subject_dn": "311f301d06035504030c162a2e776f726c646f66696e746572696f72732e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20251023000000",
      "not_after": "20261121235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/*?",
      "/auth/",
      "/account/",
      "/user/",
      "/user-context",
      "/preview/",
      "/search",
      "/product/",
      "/cdn-cgi/",
      "/services.min.js",
      "/com.condenast/yv8",
      "/reject-all",
      "*/testing-products-",
      "/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "aeed6796a0f5c0317.awsglobalaccelerator.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.wired.com/",
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
    "sitemap": {
      "urls": 60,
      "indexes": 61
    },
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
  "elapsed_s": 16.4,
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
