# Security Audit Report — canva.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://canva.com/ |
| Bug bounty program | Canva |
| Listed scope domain | canva.com |
| Test date | 2026-09-27 02:21 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 5, Info: 18)

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
| 19 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 20 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 21 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 22 | info | CT1 | 61 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 23 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
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
- **Detail:** Header reveals: CloudFront
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
- **Detail:** Apex TXT records with verification/token content: onetrust-domain-verification=155ccaa6043f43439fb8fdbd4b1be792; zoom-domain-verification=ZOOM_verify_108a73b936394b4d83555479d9dab5f2; parallels-domain-verification=f1c1fd03c9524b068006530a9bb9e5c99bb75ed2d50b4249aa
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 108 disallow path(s), e.g. Disallow:, /template/*, /_ok, /_blank, *v=
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.137.19 carries PTR server-3-169-137-19.tpe54.r.cloudfront.net. for canva.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for canva.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on canva.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 20. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of canva.com is http://ocsp.r2m04.amazontrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 21. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of canva.com discloses a 1-hop fronting chain (1.1 1054be158614657053b72dd0270b44f4.cloudfront.net (CloudFront)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 22. [INFO] 61 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: careers.canva.com, docs.developer.canva.com, l.support.canva.com, shop.canva.com, status.canva.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 23. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: careers.canva.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "canva.com",
  "dns": {
    "a": [
      "3.169.137.19",
      "3.169.137.126",
      "3.169.137.43",
      "3.169.137.106"
    ],
    "aaaa": [
      "2600:9000:284f:c400:b:add6:7500:93a1",
      "2600:9000:284f:4e00:b:add6:7500:93a1",
      "2600:9000:284f:1600:b:add6:7500:93a1",
      "2600:9000:284f:200:b:add6:7500:93a1",
      "2600:9000:284f:c200:b:add6:7500:93a1",
      "2600:9000:284f:9e00:b:add6:7500:93a1",
      "2600:9000:284f:e400:b:add6:7500:93a1",
      "2600:9000:284f:fe00:b:add6:7500:93a1"
    ],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1421.awsdns-49.org.",
      "ns-730.awsdns-27.net.",
      "ns-1851.awsdns-39.co.uk.",
      "ns-253.awsdns-31.com."
    ],
    "caa": [],
    "spf": [
      "v=spf1 include:_spf1.canva.com include:_spf2.canva.com include:_spf3.canva.com include:_spf4.canva.com include:_spf5.canva.com include:_spf6.canva.com include:_spf7.canva.com include:_spf8.canva.com include:_spf9.canva.com -all",
      "onetrust-domain-verification=155ccaa6043f43439fb8fdbd4b1be792",
      "zoom-domain-verification=ZOOM_verify_108a73b936394b4d83555479d9dab5f2",
      "docusign=4c293e32-cbde-4ddf-bec8-79108891d648",
      "parallels-domain-verification=f1c1fd03c9524b068006530a9bb9e5c99bb75ed2d50b4249aa50d897b66cc8d8",
      "google-site-verification=bQC1cPBMACHUOt271BPTfL6k2qsoXlrHkNNTW0bVGKg",
      "stripe-verification=f4e689eb94442db29e022a6d99d0d5225c45eb72488d9fdf1510b94fe6e85694",
      "google-site-verification=OORAEPphyRjSBXDWDBGtbZo0oElHFsUfxPQBesBvU6s",
      "google-site-verification=MJYHtvI-o93g5yti0Uey9u-hglJQ6UnPfV0djrxlT9M",
      "elevenlabs=P6f8fr3lI9xEMWdES8L3qlVe_hOiMQs7DN9MRcIhYx4",
      "facebook-domain-verification=05c971f78w3exkut5f717mw8obqmf3",
      "docker-verification=5298cfeb-b2af-4973-a4ae-72cfba77efa8",
      "gauntlet-domain-verification=H9sUOdHq/SMDoMyBvXJiKkoNcY9g+3uSQ17NNxJ/kY37wSJe8i7D9x50SuXPMSV0T8mxcFjDlUX+EVhpt+99Gg==",
      "hubspot-developer-verification=NDU5MWU5ODItY2E1Zi00YTY0LWEwNGEtNWU5M2EzOGIwZDll",
      "google-site-verification=eAc0jqdGQQKV0P-Rce35fFYWbiRi-Ic4QZocWJC45OE",
      "mgverify=34d839e7ad9cdafaaccc77da386dcff2c46e4a628449d8e434cd13b032c82201",
      "google-site-verification=xDNuQ7HHiwzDPok6K8T5BcxOhJ5fB0IL9vf2xLc0YAs",
      "monday-com-verification=LnZZjRw2c6n_jXge5OWXu9GWtGGjlxNtMteJuNqM0bQ",
      "cdc0ecd8-b767-4b2a-961d-056ff91c50cf",
      "stripe-verification=5d4f5c71179a849cf68764a56809bfaada60fd51ca9a6c5b881b7477dbe92f70",
      "hubspot-domain-verification=ZGM1Zjc3YzktNjdmZC00N2JlLThiOTQtY2ViZjI2NTA2OTQw",
      "neat-pulse-domain-verification-KX9q8nX=db71101a-781f-4da4-86ad-2fe12ade2c34",
      "google-site-verification=hZFAMgOOsawLXNZFTJ5XAsml2KJc5leHofbwIiLCl00",
      "google-site-verification=1uigN3ZKYSw5lr4ZdVugeteeJpy31qMbRecLJ_1ZVJU",
      "google-site-verification=YGcdBuAhkMJMRa5khtl9hTKLAHlayiapf0pxJph2ZcU",
      "twilio-domain-verification=f221ae68020aa3916d82bef6ca2fcbc0",
      "hubspot-developer-verification=ZWRmOWRlMjEtZGU1Zi00MTJiLWE4YjktNWQ3NmIyNDA5NDhm",
      "1password-site-verification=CEUWLSG27ZBI3NCDNFPDQXMJBY",
      "atlassian-domain-verification=rie8jGbQjxwFnUfEJ5DhYCdtEResa9Vg773/vaE2DtJwnEbS2txPvtfkuKhhLPTI",
      "pinterest-site-verification=b91a2bb89d0241853d81d959d5a78f07",
      "google-site-verification=2dvQv03NLacULRWLTE7UGnoYc0P18AKoAAg91FRtOTo",
      "status-page-domain-verification=fgb6hyksgk8x",
      "google-site-verification=0UOVvHC1k0nMb_2YKhFkMRkp4yRlqN-9Va_WB8b1qV0",
      "google-site-verification=bn-oB_Sgkg-cPqCil91EY6tVtaRlq2x68HktpHFloeM",
      "liveramp-site-verification=7cfkiVRS0afhs5IQ7o96bHcblYCH-SI_0G-eu7r9LsM",
      "https://issues.sonatype.org/browse/OSSRH-53881",
      "airtable-verification=e13696d96fe5c6f38c47676debdd401e",
      "postman-domain-verification=de148d23ecf7857ca6894818bd6b04d811b8e7bebcd91e5060df8aee3824726c7cdc06b72d0197a2826fd99d08a687f4cd739c2af0b7894e81bffeaf880b818c",
      "google-site-verification=vGYy48g7sb4flIluKql8BFp3_6lKKjbQEUGHUDSxCdA",
      "have-i-been-pwned-verification=b633a4fdd0ff3575f1580524a28c9c7d",
      "lucidlink-verification=Q8D0J05EK61V0PE82T654XJBMC",
      "browserstack-domain-verification=24f3b7bc-a461-4340-aa4b-dbf671f16381",
      "google-site-verification=CVeAVsJ3_hxhfhDQTbtvIbpzUIIvUZ03vQCSCx7fCZk",
      "wiz-domain-verification=7fe44deeceff62c6c3011ccf4b4ddae2fd6e94b39ec8cb2cb7e3343dc624d9c3",
      "shopify-verification-code=VFL6jPSmWRU2VUyhiN8qIQTeSnfgpA",
      "google-site-verification=ZZHXa27FmPeiiZ1sM6N3i3widAseyqpbpp5mfW18q5A",
      "detectify-verification=79cd57657f82d1fbb417ce3beec7cbe6",
      "mongodb-site-verification=stxOuL7yJeLEHCRwM4KlS0w3Qn5QDXkt",
      "MS=ms92090372",
      "openai-domain-verification=dv-X62J0FmW8lDn4eDouDTtdvnm",
      "tiktok-developers-site-verification=bTjMTogvil8AGPOJ6A2pysQYv811Q0ie",
      "stripe-verification=bbf18c986f16d71344fe2d0a77ef8b893ad8083e09a53e5fb59a864553c49921",
      "drift-domain-verification=9cea5d6a9cc67d7d8195abc4b7afefed111d50ad43225041c8d5f7fb7c2f6775",
      "cursor-domain-verification-eb1g1h=nven1Rl68xcItm0SV3eqGeGaU",
      "bugcrowd-verification=400b9a149f7cdd8664c2e7e502482536",
      "google-site-verification=TwtsJNfrmc2RPw6q28QiKM-wnDaowIdVWWX7VhmTDvA",
      "google-site-verification=a9fY2y2BlMyyaiLXgGNEIwYe80ZXchnC3Fib7-7CN30",
      "adobe-idp-site-verification=2be841675181663752bc242d59d2428df60b607824db83ed808c220becc78765",
      "mongodb-site-verification=wUQ4V3GaUzBwppXzin6kKc9AybLlHJ14",
      "onetrust-domain-verification=857af271813b4850b88f8e48bc2b2e78",
      "google-site-verification=Nj3tLWEXpg6645jNi89eJ4d-f3EKhg0mywGniT6cnP0",
      "google-site-verification=Y907KhOV3MD6WEXxbbTsYtSj1k5r3lDAVtM7bT8Tw58",
      "apple-domain-verification=AAz7BIDOOK5bj9VF",
      "yahoo-verification-key=fksNKRwkSoLGj4TIoVX0Iybviy7x0xpgDkRv/8s9Vw4=",
      "google-site-verification=DW2cTgo6bXtus9wdZWW_20IB3HhMUoH2dLyitWm5VZU",
      "google-site-verification=JqtkyfjBz-Uq1Xqk7REatNCxZnlo4gYFis8EdI_gVQ0",
      "stripe-verification=15ef6563e51240246ef5c70232027055e35f306d5a68e239ba4d60b65b5e8f46",
      "google-site-verification=MfIUBrtfhRkfARKs7m47C8eRPrJet6cRCq8M18-bHLo",
      "stripe-verification=ec89fd8a56a7c9b8a0271fb890adecdfe20b8c157ade22d326b0ab9389b43f9b",
      "ahrefs-site-verification_801b8774fd779b395b1c81e48f7900e305369a5ed19eb3201a3dbc918465f5de",
      "airtable-verification=a351d73cf64b3a7900588fe07af4eca6"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@canva.com; ruf=mailto:dmarc-reports+forensics@canva.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=canva.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Nov 18 00:00:00 2025 GMT",
    "notAfter": "Dec 17 23:59:59 2026 GMT",
    "san": [
      "canva.com"
    ],
    "days_left": 81,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.137.19",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.canva.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://canva.com/"
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
    "count": 61,
    "notable": [
      "careers.canva.com",
      "docs.developer.canva.com",
      "l.support.canva.com",
      "shop.canva.com",
      "status.canva.com"
    ],
    "sample": [
      "about.canva.com",
      "ar-eg.about.canva.com",
      "assistant-data-bucket.canva.com",
      "attend.canva.com",
      "canva.com",
      "careers.canva.com",
      "create-stg.canva.com",
      "create.canva.com",
      "creator.canva.com",
      "cse.canva.com",
      "ct.canva.com",
      "designschool.canva.com",
      "developer.canva.com",
      "docs.developer.canva.com",
      "document-content-amzn.canva.com",
      "document-content-apne1.canva.com",
      "document-content-apse2.canva.com",
      "document-export-amzn.canva.com",
      "document-export-apne1.canva.com",
      "document-export-apse2.canva.com"
    ],
    "dangling": [
      "careers.canva.com"
    ]
  },
  "apex_txt": [
    "onetrust-domain-verification=155ccaa6043f43439fb8fdbd4b1be792",
    "zoom-domain-verification=ZOOM_verify_108a73b936394b4d83555479d9dab5f2",
    "parallels-domain-verification=f1c1fd03c9524b068006530a9bb9e5c99bb75ed2d50b4249aa",
    "google-site-verification=bQC1cPBMACHUOt271BPTfL6k2qsoXlrHkNNTW0bVGKg",
    "stripe-verification=f4e689eb94442db29e022a6d99d0d5225c45eb72488d9fdf1510b94fe6e8"
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
      "serial": 10995900519342731596246826860888089454,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "san": [
        "canva.com"
      ],
      "subject_dn": "311230100603550403130963616e76612e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20251118000000",
      "not_after": "20261217235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "Disallow:",
      "/template/*",
      "/_ok",
      "/_blank",
      "*v=",
      "*utm_expid=",
      "*source=",
      "*utm_source=",
      "*utm_campaign=",
      "*utm_content=",
      "*__hstc=",
      "*reviews_page=",
      "*gclid=",
      "*magazineName=",
      "*_ga="
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-3-169-137-19.tpe54.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.canva.com/",
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
    "root_status": 301,
    "cdn": [
      "CloudFront",
      "Fastly"
    ]
  },
  "x17": {
    "ocsp_http": "http://ocsp.r2m04.amazontrust.com",
    "via": "1.1 1054be158614657053b72dd0270b44f4.cloudfront.net (CloudFront)"
  },
  "elapsed_s": 4.7,
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
