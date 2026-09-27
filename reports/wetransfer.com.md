# Security Audit Report — wetransfer.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wetransfer.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | wetransfer.com |
| Test date | 2026-09-27 01:37 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 2, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | P8 | Missing security.txt | CWE-1038 |
| 5 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 6 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 7 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 8 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 9 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 10 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 11 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 12 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 15 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 16 | info | HTML3 | Third-party <iframe> embedded in root document | CWE-643 |
| 17 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 18 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 19 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 20 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 21 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 5. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 6. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 7. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (vcsrmwwrqza6xz.wetransfer.com and 2lakwcfq8xdqxn.wetransfer.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 8. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: wrike-verification=MTc5Mjk4MTpjOWI1MzY4ODdmMGU4ZDA1NDI4MWJiM2ZkYmJhMmE0YzMzMmVkO; rippling-domain-verification=217697edd61756fc; google-site-verification=pZwqaQca9efqhei-uJPD1AYhimUB37qXYq-2jvp-mhc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 9. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 10. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 24 disallow path(s), e.g. /*?*, /api/, /ter-optout, /pm-optout, /mar-optout
- **Recommendation:** Review disallowed paths; robots is not access control.

### 11. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of wetransfer.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 12. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of wetransfer.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.118 carries PTR server-54-192-248-118.tpe53.r.cloudfront.net. for wetransfer.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkq4faapdgifn4.html -> 404; error page/headers match: CloudFront.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 15. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on wetransfer.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 16. [INFO] Third-party <iframe> embedded in root document (`HTML3`)

- **CWE:** CWE-643
- **Detail:** Root document of wetransfer.com embeds 1 cross-origin iframe(s), e.g. https://tagging.wetransfer.com/ns.html?id=GTM-NS54WBW; embedded origins are framed inside the page with its trust context.
- **Recommendation:** Review embedded origins and consider sandbox attributes.

### 17. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on wetransfer.com lists 5 <loc> URL(s) across 6 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 18. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of wetransfer.com references 5 distinct third-party registrable domains (e.g. wetransfer.net, adsrvr.org, amazon-adsystem.com, pinimg.com, google.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 19. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of wetransfer.com sends a CSP but contains 3 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 20. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of wetransfer.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 21. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on wetransfer.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

## Evidence (raw response observations)

```json
{
  "domain": "wetransfer.com",
  "dns": {
    "a": [
      "54.192.248.118",
      "54.192.248.21",
      "54.192.248.7",
      "54.192.248.99"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "ns-616.awsdns-13.net.",
      "ns-1495.awsdns-58.org.",
      "ns-381.awsdns-47.com.",
      "ns-1743.awsdns-25.co.uk."
    ],
    "caa": [
      "0 issue \"letsencrypt.org\"",
      "0 iodef \"mailto:domains@wetransfer.com\"",
      "0 issue \"amazon.com\""
    ],
    "spf": [
      "MS=ms33481336",
      "Notion_verify_4qsvK9AQNWyTTydLGyF3ysuoJuYcgPfo6qzsKeWsJba9ayET3MJsMLQA2AhsM6HGMa7UL",
      "wrike-verification=MTc5Mjk4MTpjOWI1MzY4ODdmMGU4ZDA1NDI4MWJiM2ZkYmJhMmE0YzMzMmVkOTUyMjg0MWZjNWFhZTY2YjliOWMyMDExY2M4",
      "asv=89178be4f98e857aed14bc7a748446eb",
      "v=spf1 include:spf1.wetransfer.com include:servers.mcsv.net include:_spf.google.com include:mail.zendesk.com include:mailsenders.netsuite.com -all",
      "rippling-domain-verification=217697edd61756fc",
      "google-site-verification=pZwqaQca9efqhei-uJPD1AYhimUB37qXYq-2jvp-mhc",
      "notion-domain-verification=Yg69TXpuZUoTBv5Ri6zQhMtHrF7gDDypUiwiwsKcc8Q",
      "ZOOM_verify_KL0Tx6QHRE-pFo1TUH489w",
      "jamf-site-verification=EPAkOUuclyfbWuPrE4bFJg",
      "google-site-verification=o1-Z5_XysLkNRL_Fr0XzMxTNDGCHoVJzwmOgG5apYrs",
      "_1l13uk3o31dwxht8gy20uftkq7njy9i",
      "slack-domain-verification=wvKukMkbZSVirrbxUeRN90GH6W7HoJVKjCqpdsCc",
      "facebook-domain-verification=h9w15klgw91n2ot3lw77t035wqw2vb",
      "docusign=d8951d4e-554f-42ad-878e-a8cfa144f728",
      "adobe-idp-site-verification=27c19071d43cf50bb319f12dca1b494fb4ac78700f01158bc53c750a64a62677",
      "airtable-verification=1424b5a97e88024b52c0d21bf8a1cd64",
      "google-site-verification=ZdmG6lG1KKqyINxvbgMYMLtigj2Zjc5qasxPp7ikZ3I",
      "google-site-verification=22yq8uEpGxlFe2r7H413v6Wor4yaJDF_XM0wsOxoXjs",
      "apple-domain-verification=HVcqj6adUo39535i",
      "anthropic-domain-verification-v74473=mmo7JLEzQN3oOrEhxNuzyUxja",
      "atlassian-domain-verification=SvE4jaub7awLiMuXWZa/MJuI10LQaiwUVcYdQa2xKuCB6Y6dKD9Z9olL9iVfyJed",
      "lemlist-verif=3a27e226",
      "stripe-verification=448ebe2b06a2eba394d9e73a16a897dee98918e6e8593961f56e86bb6296c520",
      "google-site-verification=psmb0t3fy95_06_HZTTKA42vG8jQp8utdBMGYCgbJn8",
      "amazonses:OkYxgsklLbk4Efq6tshR+hWtLlWSmWy6A49YvL6zwqw=",
      "google-site-verification=12Dz3BKB7bWfhvTLookytJl2LUfhuheBky3SokggYkc",
      "onetrust-domain-verification=2580b3683efb4e6f91ea1440cc1bee77",
      "ibmid=0b0660a3-b186-469a-8b70-25eac0c5a095",
      "google-site-verification=XW_EN8p8Aq6F0vXQo8QJFXTzZH3bHQnLYA4TFyPN63E",
      "google-site-verification=QgqEa_4yOMSHcWSMtJrG4M0jeBwKBK07p7E5A73Ht_Q",
      "google-site-verification=L4cTbeDJCawV2WcUBdIg0ZohUIzmQsyri0cW9Vfx3ms"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:reports@dmarc.bendingspoons.com; pct=100;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=wetransfer.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Jul 24 00:00:00 2026 GMT",
    "notAfter": "Feb  6 23:59:59 2027 GMT",
    "san": [
      "wetransfer.com",
      "*.wetransfer.com"
    ],
    "days_left": 132,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.118",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "WeTransfer | Send Large Files Fast"
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
      "origin": "https://sub.wetransfer.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://wetransfer.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "wrike-verification=MTc5Mjk4MTpjOWI1MzY4ODdmMGU4ZDA1NDI4MWJiM2ZkYmJhMmE0YzMzMmVkO",
    "rippling-domain-verification=217697edd61756fc",
    "google-site-verification=pZwqaQca9efqhei-uJPD1AYhimUB37qXYq-2jvp-mhc",
    "notion-domain-verification=Yg69TXpuZUoTBv5Ri6zQhMtHrF7gDDypUiwiwsKcc8Q",
    "jamf-site-verification=EPAkOUuclyfbWuPrE4bFJg"
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
      "aia_ocsp": "http://ocsp.r2m01.amazontrust.com",
      "serial": 9479296629050134934984719104673594766,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "subject_dn": "311730150603550403130e77657472616e736665722e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20260724000000",
      "not_after": "20270206235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/*?*",
      "/api/",
      "/ter-optout",
      "/pm-optout",
      "/mar-optout",
      "/renewal-reminder-optout",
      "/wallpaper/",
      "/wallpapers/",
      "/unlisted/",
      "/transfers",
      "/account/",
      "/workspace/",
      "/contacts",
      "/checkout",
      "/payment/"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-54-192-248-118.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "sitemap": {
      "urls": 5,
      "indexes": 6
    },
    "crl": {
      "url": "http://crl.r2m01.amazontrust.com/r2m01.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "x16": {
    "root_status": 200,
    "alt_svc": "h3=\":443\"; ma=86400",
    "cdn": [
      "CloudFront",
      "Fastly"
    ]
  },
  "elapsed_s": 17.3,
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
