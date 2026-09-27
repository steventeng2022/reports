# Security Audit Report — stripe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stripe.com/ |
| Bug bounty program | Stripe |
| Listed scope domain | stripe.com |
| Test date | 2026-09-27 01:34 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 1, Info: 17)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H6 | Server technology disclosure | CWE-200 |
| 5 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 6 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 7 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 8 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 9 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 10 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 11 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 12 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 13 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 14 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 15 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 16 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 17 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 18 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 5. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 6. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 7. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ZgGi2-xDdfnaWxdfjn5AqtUS11jKWqSXAV_EHODFzdE; facebook-domain-verification=m7id9rt8ehlgcg9tt2yggbsi6gro7i; neat-pulse-domain-verification-8GMn8nv=36eba03d-345e-421a-a823-d6d1f28938a4
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 8. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 17 disallow path(s), e.g. /docs, /docs$, /bitcoin/refund, /sources/refund, /sources/sepa_mandate
- **Recommendation:** Review disallowed paths; robots is not access control.

### 9. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of stripe.com permits unsafe-inline; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 10. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of stripe.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 11. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk8l3u1fc0d26g.html -> 404; error page/headers match: Nginx.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 12. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/assetlinks.json on stripe.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 13. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The stripe.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 14. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of stripe.com loads 78 cross-origin script(s) without an integrity attribute, e.g. https://b.stripecdn.com/mkt-ssr-statics/assets/_next/static/chunks/polyfills-42372ed130431b0a.js, https://b.stripecdn.com/mkt-ssr-statics/assets/_next/static/chunks/22074.bd02a94640605868.js, https://b.stripecdn.com/mkt-ssr-statics/assets/_next/static/chunks/49450.ba8bdeacb2ae3f4e.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 15. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on stripe.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 16. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of stripe.com references 15 distinct third-party registrable domains (e.g. stripecdn.com, w3.org, stripeassets.com, youtube.com, schema.org); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 17. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of stripe.com sends a CSP but contains 2 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 18. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of stripe.com declares preconnect/dns-prefetch/modulepreload for 1 third-party registrable domain(s) (e.g. stripeassets.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

## Evidence (raw response observations)

```json
{
  "domain": "stripe.com",
  "dns": {
    "a": [
      "198.202.176.231",
      "198.137.150.231"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns-423.awsdns-52.com.",
      "ns-1882.awsdns-43.co.uk.",
      "ns-1087.awsdns-07.org.",
      "ns-705.awsdns-24.net."
    ],
    "caa": [
      "0 issue \"digicert.com\"",
      "0 issue \"visa.com\"",
      "0 iodef \"mailto:caa-violations@stripe.com\"",
      "0 issue \"amazon.com\""
    ],
    "spf": [
      "google-site-verification=ZgGi2-xDdfnaWxdfjn5AqtUS11jKWqSXAV_EHODFzdE",
      "facebook-domain-verification=m7id9rt8ehlgcg9tt2yggbsi6gro7i",
      "neat-pulse-domain-verification-8GMn8nv=36eba03d-345e-421a-a823-d6d1f28938a4",
      "apple-domain-verification=8kIS0gmJTvILWQuI",
      "vercel-domain-verification-n462w8=JRePwTQbccpon6VAqYhidisHw",
      "v=MCPv1; k=ed25519; p=WMeka0C1fIH9HQLMtsSM9DD9cM6Bz6Wz34mHnK86UcM=",
      "vercel-domain-verification-9rcztj=vE2uCkG0lJyU17dOW1DamoD7v",
      "h1-domain-verification=KhpNX9YNAc7bX95agGvFsPPKbYTVe1KC6xj7P1zKZrRzxcuS",
      "atlassian-domain-verification=upLp21qQgja1aHG2gnAb1AmXRqb/zG0UK1a0n3zTSXZg5DgOSttR3i5uzA3T9Cdk",
      "anthropic-domain-verification-zk7x9c=QfN52ECybLPUWh51R9pKF0QO3",
      "MS=ms80697640",
      "openai-domain-verification=dv-9tiBE20GDN0Td9lCfVtA3DwG",
      "edcbf4c7-b604-457b-870e-1b05f655e769",
      "cursor-domain-verification-vncvvm=D0NzeIDbQa8PPgIf1ukp9UPiu",
      "stripe-verification=82ce82470fb8324e19fa65abdb6fd370da5a8f90bba09712f259760f625d0790",
      "v=spf1 ip4:198.2.180.60/32 ip4:13.111.2.227/32 include:spf1.stripe.com include:greenhouse-outbound-mail.stripe.com include:_spf.qualtrics.com ~all",
      "google-site-verification=hPfjsDwiisKJ4RP1ExOst9gAOD_0P8Q7-kxdcKUvEcc",
      "canva-site-verification=xLypn0D9XANRy-lbwcMfHA",
      "asv=8de0c1a866b958297e22a36216e594a6",
      "elevenlabs=NpcIkVJW_8Vyd2gLKzPviuaU1g5rz83KiWQQ3sWKGtI",
      "google-site-verification=PrlpJHdk11CIkPsiXoHEAJevWHAk39JRFAqVSe9l7n0",
      "liveramp-site-verification=7gyFkTwGYsvgd7IUQwyAOfImETwR06wgKjKiXq90KEY",
      "fastly-domain-delegation-3c9tdnjzdwy7wfffvyyy-786084-2024-07-08",
      "00D50000000JV6w=1TBTQ0000000CIv;00DDn000000HWol=1TBVY00000002Hx;00D4x000003vxGL=1TBPQ00000008Tp;00Dfn00000BUlWD=1TBan0000000LPR",
      "whimsical=253112f9add9790f3a27b9d9893626451fc4cda1",
      "google-site-verification=NLkFgZLHeVMVYlR3t1UZC9_1LzmqCAefJyNDs6ZQqBA",
      "docusign=4a93db58-af07-4632-a881-b569d41a6c57",
      "vercel-domain-verification-d2ks5d=rkbS4OdBoLxPogGq2IhBN1OZV",
      "VISA=38A3D7A1AA5D71E43525144DD886F6B8",
      "google-site-verification=qjP3OAiraClha_40cX9Z9FrG5q3O_0InXSamXOswY-s",
      "vercel-domain-verification-0x8270=XezzJjJYrYZwY6CahDneh2ruB",
      "linear-domain-verification=prudk75mtrrj",
      "z4mthhzk10l6qc0rg4211mnnppkh2y5b",
      "docusign=4c9f5602-1c19-4e4c-bde7-77dc4b9ea8a0",
      "_2m7hdcar6jar33f5vyr8h0xaru6rvrn",
      "google-site-verification=pmz8ueKvWMPxNlwUDcVroF91-tq6I9VM6wSO_0i7-wc",
      "_c2ygqoyhcuwjjnqk7h1mcm0x144rm1z",
      "postman-domain-verification=c3b168067b16085c452b04b643ae1000079b095e383b53d1074e409b0e600b6265e1c7963beca1ca87cc63c381dcea332544c92c919651e4cda69f9a6303079c",
      "docker-verification=ccde1a0d-8d2c-44b5-9d20-6c4e19113fc9"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc-reports@stripe.com; ruf=mailto:dmarc-forensics@stripe.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "jurisdictionCountryName=US, jurisdictionStateOrProvinceName=Delaware, businessCategory=Private Organization, serialNumber=4675506, countryName=US, stateOrProvinceName=California, localityName=South San Francisco, organizationName=Stripe, LLC, commonName=stripe.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Aug 17 00:00:00 2026 GMT",
    "notAfter": "Nov 12 23:59:59 2026 GMT",
    "san": [
      "stripe.com",
      "www.stripe.com"
    ],
    "days_left": 46,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "198.202.176.231",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Stripe | Financial Infrastructure to Grow Your Revenue"
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
      "origin": "https://sub.stripe.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://stripe.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=ZgGi2-xDdfnaWxdfjn5AqtUS11jKWqSXAV_EHODFzdE",
    "facebook-domain-verification=m7id9rt8ehlgcg9tt2yggbsi6gro7i",
    "neat-pulse-domain-verification-8GMn8nv=36eba03d-345e-421a-a823-d6d1f28938a4",
    "apple-domain-verification=8kIS0gmJTvILWQuI",
    "vercel-domain-verification-n462w8=JRePwTQbccpon6VAqYhidisHw"
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
      "serial": 15397287057475171462479262729239681386,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
        "http://crl4.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl"
      ],
      "subject_dn": "31133011060b2b0601040182373c0201031302555331193017060b2b0601040182373c020102130844656c6177617265311d301b060355040f0c1450726976617465204f7267616e697a6174696f6e3110300e0603550405130734363735353036310b3009060355040613025553311330110603550408130a43616c69666f726e6961311c301a06035504071313536f7574682053616e204672616e636973636f31143012060355040a130b5374726970652c204c4c43311330110603550403130a7374726970652e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473320544c532045434320534841333834203230323020434131",
      "not_before": "20260817000000",
      "not_after": "20261112235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/docs",
      "/docs$",
      "/bitcoin/refund",
      "/sources/refund",
      "/sources/sepa_mandate",
      "/sources/test_source",
      "/sources/test_klarna",
      "/handoff-healthcheck",
      "/handoff",
      "/bitcoin/refund",
      "/sources/refund",
      "/sources/sepa_mandate",
      "/sources/test_source",
      "/sources/test_klarna",
      "/unsupported-browser"
    ]
  },
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
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
    "root_status": 200,
    "hsts": "max-age=63072000; includeSubDomains; preload",
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "preconnect": [
      "stripeassets.com"
    ]
  },
  "elapsed_s": 23.5,
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
