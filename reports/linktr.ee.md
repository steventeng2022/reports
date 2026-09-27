# Security Audit Report — linktr.ee

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://linktr.ee/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | linktr.ee |
| Test date | 2026-09-27 02:36 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 1, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | P8 | Missing security.txt | CWE-1038 |
| 6 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 7 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 8 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 9 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 10 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 11 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 12 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 13 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 14 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 15 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 16 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 17 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 18 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 19 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |
| 20 | info | CT1 | 53 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 6. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 7. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 8. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: attio-domain-verification=UHX2B6D5TX6CX53CXGBAHGW3; anthropic-domain-verification-1tycht=zJnYXvMUrBuyoLB4eKC6V1Wav; loom-site-verification=1c1e2086449545d190b57b810de3c741
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 9. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of linktr.ee has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 10. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 229 disallow path(s), e.g. /admin$, /admin/, /admin?, /s/about/trust-center/report, /admin$
- **Recommendation:** Review disallowed paths; robots is not access control.

### 11. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://linktr.ee/ carries Cache-Control: max-age=0, must-revalidate (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 12. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on linktr.ee; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 13. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for linktr.ee, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 14. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of linktr.ee references 13 distinct third-party registrable domains (e.g. schema.org, apple.com, google.com, googletagmanager.com, datagrail.io); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 15. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of linktr.ee sends a CSP but contains 10 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 16. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to linktr.ee negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 17. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on linktr.ee identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 18. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of linktr.ee declares preconnect/dns-prefetch/modulepreload for 1 third-party registrable domain(s) (e.g. datagrail.io); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 19. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of linktr.ee discloses a 2-hop fronting chain (1.1 varnish, 1.1 varnish); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

### 20. [INFO] 53 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: assets.production.linktr.ee, assets.qa.linktr.ee
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "linktr.ee",
  "dns": {
    "a": [
      "151.101.2.133",
      "151.101.130.133",
      "151.101.66.133",
      "151.101.194.133"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-1782.awsdns-30.co.uk.",
      "ns-634.awsdns-15.net.",
      "ns-169.awsdns-21.com.",
      "ns-1534.awsdns-63.org."
    ],
    "caa": [],
    "spf": [
      "attio-domain-verification=UHX2B6D5TX6CX53CXGBAHGW3",
      "MS=ms25160908",
      "v=spf1 include:sendgrid.net include:hs.linktr.ee include:_spf.google.com -all",
      "anthropic-domain-verification-1tycht=zJnYXvMUrBuyoLB4eKC6V1Wav",
      "loom-site-verification=1c1e2086449545d190b57b810de3c741",
      "google-site-verification=M0XDPVdF5XBrnb-68KdBWmKi35ovRf_PqZM6zRj6xfo",
      "google-site-verification=c_BBAAGdYj2L7cOpPgNF76jiXnFUVS_Xz5gfcBOmGL4",
      "google-site-verification=5_2gPClKT1kQHILAWOrq9g-MDZQpYTvUvAMV5lADcHU",
      "Validity-Domain-Verification=6HrSbK1DTz+C/kYrvt2yxBW93F4=",
      "google-site-verification=J_OCvoB105vcwDCwwO0xZlxvWZLz6-UzS4UssSeiy-U",
      "hubspot-domain-verification=MTQzMjVkY2EtZDc5YS00ZmMwLTgzNmMtODJhZWFhNjQ1MTFi",
      "google-site-verification=oJ0isC1gRFlJdV5L_p5ObuVX0JCcyzPQ2N4FcdFSY-c",
      "h1-domain-verification=HDHQ9deSLqK9KYahSa9UU559PvrgNBi3T1zdN9Lj8CVoYCV8",
      "tiktok-developers-site-verification=5TpDHtevdeyto1s53FrggeA4rqLMU34r",
      "stripe-verification=0AB4346953316F0622DA92E369CDFA951C54E959A15CC1CFB96E49D02E203691",
      "stripe-verification=28e5f4ef1feaccb632b7affa6996c5fd43b1e4fafe6b87fe7fa34543a77f090a",
      "slack-domain-verification=62Jx5SGkgzgdLmF6mYPo1oWMHoLI1PGqzxt71dYk",
      "tiktok-developers-site-verification=HhSSn99SRimgJNJJkcm0Rt0tjhOiMLW5",
      "google-site-verification=-3XY-ldZZm2O8v9blT-mMiBduUxNdPsrrFXneZFHJNU",
      "amazon-business-verification=16012857de4a76553695df824bae16348649f39cf989c2354b5bc7cd379b15e9",
      "stripe-verification=15f31e50c5710252111569ad76dfd30414dfe84321fddd6fb2f7cf42ced4e306",
      "ZOOM_verify_FEdjcGCXQD7LtbPD7NDAPO",
      "google-site-verification=BqwBT-jSv9iENaqGfI_gbooYEjs3uUHh-lXpVf8tkJk",
      "uber-domain-verification=88d7ba7b-2a23-42ae-ba4f-e96706f6b728",
      "_5gpstlp0j1ze117x41vpd77qfn3qn6q",
      "stripe-verification=61B436C0036D8172284A969CE10CED7FFF67D38B204B51F49A0A2C3D3C65805B",
      "stripe-verification=85AF8598246098631ED129FA3218F6C4DA2CFEC57DD8A9F080110B8CA399D2DD",
      "zoom-domain-verification=ZOOM_verify_3d500f8c401c445e9cc337e189236ef5",
      "openai-domain-verification=dv-PfCKEtIOkYIRSjuyixJqqZcf",
      "google-site-verification=ictM7BaxKAXWoNxeAH2qUWzbIWwUZT0krATNluy2hwg",
      "google-site-verification=tOpEoiVk37-4HaCFCMb86Q2F9zpl4gh0cF9PvQjJ5aw",
      "google-site-verification=JnB4sONl0K7d3wGyRs9an0C0VJFVhhmGSjf5diV790k",
      "onetrust-domain-verification=e0ec11d4d77546b791a0f946a32a6c1e",
      "wiz-domain-verification=993ae6f241de2f53ea30277e8fb8042709252ec68b523cf26181b4cbef0a0a0c",
      "facebook-domain-verification=8ssyxgwhdjg409vl1qwv8tqy6745zy",
      "dropbox-domain-verification=831j6zm4fvfj",
      "stripe-verification=731DF94DEAEA1EAAA807EAE7D72D7338E193CD76AE97150ECF41896807B1B033",
      "stripe-verification=58C8428D5C7E162ADE166B3F34072EC21AA64FE97D46970CC352FAB198CC1F9E",
      "notion_verify_LZm1CNzi_RmH#UCV.uR1MvXKsWEG8nebvc}bw+TYMj)mzgrf33H1tUkj*g@r37^#nuKBqT",
      "t252Y1nfZvxjX0093cC7cncQHg"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@dmarc.everest.email,mailto:dmarc@linktr.ee;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=linktr.ee",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 29 01:38:02 2026 GMT",
    "notAfter": "Nov 27 01:38:01 2026 GMT",
    "san": [
      "linktr.ee"
    ],
    "days_left": 60,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.2.133",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Link in bio tool: Everything you are, in one simple link | Linktree"
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
      "origin": "https://sub.linktr.ee",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://linktr.ee/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 406",
    "/redirect?next=https://evil-auditor.example/x -> 406",
    "/go?url=https://evil-auditor.example/x -> 406",
    "/url?url=https://evil-auditor.example/x -> 406"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 406,
    "/.well-known/security.txt": 404,
    "/security.txt": 406,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 406,
    "/.htaccess": 200,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 53,
    "notable": [
      "assets.production.linktr.ee",
      "assets.qa.linktr.ee"
    ],
    "sample": [
      "app-store-storybook.qa.linktr.ee",
      "assets.production.linktr.ee",
      "assets.qa.linktr.ee",
      "authiamapi.qa.linktr.ee",
      "bluegreen.monolith.qa.linktr.ee",
      "brand-portal-origin.production.linktr.ee",
      "brand-portal-origin.qa.linktr.ee",
      "chat-mcp-openai-app.production.linktr.ee",
      "chat-mcp-openai-app.qa.linktr.ee",
      "chat-public.production.linktr.ee",
      "chat-public.qa.linktr.ee",
      "cms.qa.linktr.ee",
      "commerce-affiliate.production.linktr.ee",
      "commerce-affiliate.qa.linktr.ee",
      "commerce-ingest.production.linktr.ee",
      "commerce-ingest.qa.linktr.ee",
      "descope-universal-login.production.linktr.ee",
      "descope-universal-login.qa.linktr.ee",
      "enrichments.linktr.ee",
      "graph-alpha.qa.linktr.ee"
    ]
  },
  "apex_txt": [
    "attio-domain-verification=UHX2B6D5TX6CX53CXGBAHGW3",
    "anthropic-domain-verification-1tycht=zJnYXvMUrBuyoLB4eKC6V1Wav",
    "loom-site-verification=1c1e2086449545d190b57b810de3c741",
    "google-site-verification=M0XDPVdF5XBrnb-68KdBWmKi35ovRf_PqZM6zRj6xfo",
    "google-site-verification=c_BBAAGdYj2L7cOpPgNF76jiXnFUVS_Xz5gfcBOmGL4"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "serial": 452957291872368627942661553985512576474452,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://yr1.c.lencr.org/85.crl"
      ],
      "san": [
        "linktr.ee"
      ],
      "subject_dn": "31123010060355040313096c696e6b74722e6565",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595231",
      "not_before": "20260829013802",
      "not_after": "20261127013801"
    }
  },
  "http2": {
    "robots_disallow": [
      "/admin$",
      "/admin/",
      "/admin?",
      "/s/about/trust-center/report",
      "/admin$",
      "/admin/",
      "/admin?",
      "/s/about/trust-center/report",
      "/admin$",
      "/admin/",
      "/admin?",
      "/s/about/trust-center/report",
      "/admin$",
      "/admin/",
      "/admin?"
    ]
  },
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 406,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "crl": {
      "url": "http://yr1.c.lencr.org/85.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_ver": "TLSv1.2",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "cdn": [
      "Fastly"
    ],
    "preconnect": [
      "datagrail.io"
    ]
  },
  "x17": {
    "via": "1.1 varnish, 1.1 varnish"
  },
  "elapsed_s": 28.4,
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
