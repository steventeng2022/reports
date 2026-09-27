# Security Audit Report — coinmarketcap.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://coinmarketcap.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | coinmarketcap.com |
| Test date | 2026-09-27 01:14 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 1, Info: 21)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H6 | Server technology disclosure | CWE-200 |
| 4 | info | P8 | Missing security.txt | CWE-1038 |
| 5 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 6 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 7 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 8 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 9 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 10 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 11 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 12 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 15 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 17 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 18 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 19 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 20 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 21 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 22 | info | CT1 | 20 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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

### 7. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=c9mql15ejmnw7ti6tks95kx46ks3jo; apple-domain-verification=IpY-v5shWd9KVeDzJPS8r0okeTIwMlDkyLmF6cNAd_w; atlassian-domain-verification=YT8U29m9J7i85eaznD4fr4n9PfcN/w3j/ZqlVYs2vG15VWL2NN
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 8. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 9. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but coinmarketcap.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 10. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 12 disallow path(s), e.g. /headlines/*, /*/headlines/*, /community/*/post/*, /community/*/live/*, /community/*/topics/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 11. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of coinmarketcap.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 12. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://coinmarketcap.com/ carries Cache-Control: public, max-age=120, stale-while-revalidate=60, stale-if-error=60 (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.121.75 carries PTR server-3-169-121-75.tpe53.r.cloudfront.net. for coinmarketcap.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkqk9z8ebe2rev.html -> 404; error page/headers match: Nginx, CloudFront.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 15. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on coinmarketcap.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for coinmarketcap.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 17. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of coinmarketcap.com loads 1 cross-origin script(s) without an integrity attribute, e.g. https://3f0fb9bcf568.edge.sdk.awswaf.com/3f0fb9bcf568/1d2f2dc6120c/challenge.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 18. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on coinmarketcap.com lists 27 <loc> URL(s) across 28 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 19. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of coinmarketcap.com references 6 distinct third-party registrable domains (e.g. w3.org, schema.org, facebook.com, twitter.com, awswaf.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 20. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of coinmarketcap.com sends a CSP but contains 8 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 21. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on coinmarketcap.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 22. [INFO] 20 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: beta.coinmarketcap.com, staging.coinmarketcap.com, status.coinmarketcap.com, support.coinmarketcap.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "coinmarketcap.com",
  "dns": {
    "a": [
      "3.169.121.75",
      "3.169.121.21",
      "3.169.121.26",
      "3.169.121.67"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)",
      "mxb-00784a01.gslb.pphosted.com (pref 1)",
      "mxa-00784a01.gslb.pphosted.com (pref 5)"
    ],
    "ns": [
      "ns-2024.awsdns-61.co.uk.",
      "ns-52.awsdns-06.com.",
      "ns-1254.awsdns-28.org.",
      "ns-763.awsdns-31.net."
    ],
    "caa": [],
    "spf": [
      "v=spf1 include:_spf.google.com include:sendgrid.net include:mail.zendesk.com include:emsd1.com include:spf-00784a01.pphosted.com -all",
      "facebook-domain-verification=c9mql15ejmnw7ti6tks95kx46ks3jo",
      "apple-domain-verification=IpY-v5shWd9KVeDzJPS8r0okeTIwMlDkyLmF6cNAd_w",
      "atlassian-domain-verification=YT8U29m9J7i85eaznD4fr4n9PfcN/w3j/ZqlVYs2vG15VWL2NNcS9c1jkIc/BP3W",
      "google-site-verification=hqUA9mBjH57N_FIJV4vkjlh_vuTGsNYJV8bErIT9izs",
      "ahrefs-site-verification_86f2f08131d8239e3a4d73b0179d556eae74fa62209b410a64ff348f74e711ea",
      "google-site-verification=Vf_mqov516xuQRQ_br3FlVER8PrZ_CaaB1OUruEjn84",
      "google-site-verification=T5ZnzNMTvLb5kdKlwTCCJUQKWXcfgiYPkr4H8O3NmNg",
      "v=MCPv1; k=ed25519; p=Xk7wX7xqTt6MDBN0Ub8A451MVUwvawWNy9364316K24=",
      "google-site-verification=h8XSgzWPJa4QZP3ZmMafldNHevrcSYnWyc5RPiEvCBQ",
      "google-site-verification=nt91clIDjoi6MbZjqG__pGlylJVSQA6ZnoenJzdWwEU",
      "google-site-verification=TcF0PnxBx5EyLHzPGz_rarl75Ea3HIHcbaO3PP7cT8s",
      "yandex-verification: fcfc1e0853947ee6"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;sp=reject;pct=100;rua=mailto:david.k@coinmarketcap.com;ruf=mailto:derek.li@coinmarketcap.com;ri=86400;aspf=s;adkim=s;fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=coinmarketcap.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jun 29 00:00:00 2026 GMT",
    "notAfter": "Jan 12 23:59:59 2027 GMT",
    "san": [
      "coinmarketcap.com",
      "cmc.ai",
      "*.coinmarketcap.com",
      "*.beta.coinmarketcap.com",
      "*.staging.coinmarketcap.com",
      "*.cmc.ai",
      "*.cmcap.io"
    ],
    "days_left": 107,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.121.75",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Cryptocurrency Prices, Charts And Market Capitalizations | CoinMarketCap"
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
      "origin": "https://sub.coinmarketcap.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://coinmarketcap.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 404,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 200
  },
  "subdomains": {
    "source": "certspotter",
    "count": 20,
    "notable": [
      "beta.coinmarketcap.com",
      "staging.coinmarketcap.com",
      "status.coinmarketcap.com",
      "support.coinmarketcap.com"
    ],
    "sample": [
      "beta.coinmarketcap.com",
      "blockchain-stable.coinmarketcap.com",
      "blockchain.coinmarketcap.com",
      "coinmarketcap.com",
      "dapi-qa.coinmarketcap.com",
      "dapi.coinmarketcap.com",
      "dex.coinmarketcap.com",
      "dws.coinmarketcap.com",
      "link.coinmarketcap.com",
      "memews-eu.coinmarketcap.com",
      "memews-us.coinmarketcap.com",
      "memews.coinmarketcap.com",
      "preview.coinmarketcap.com",
      "pro-stream.coinmarketcap.com",
      "selfserve.coinmarketcap.com",
      "staging.coinmarketcap.com",
      "status.coinmarketcap.com",
      "support-chat.coinmarketcap.com",
      "support.coinmarketcap.com",
      "web3.coinmarketcap.com"
    ]
  },
  "apex_txt": [
    "facebook-domain-verification=c9mql15ejmnw7ti6tks95kx46ks3jo",
    "apple-domain-verification=IpY-v5shWd9KVeDzJPS8r0okeTIwMlDkyLmF6cNAd_w",
    "atlassian-domain-verification=YT8U29m9J7i85eaznD4fr4n9PfcN/w3j/ZqlVYs2vG15VWL2NN",
    "google-site-verification=hqUA9mBjH57N_FIJV4vkjlh_vuTGsNYJV8bErIT9izs",
    "ahrefs-site-verification_86f2f08131d8239e3a4d73b0179d556eae74fa62209b410a64ff348"
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
      "serial": 15162665105120792542739025492040008614,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "subject_dn": "311a301806035504031311636f696e6d61726b65746361702e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20260629000000",
      "not_after": "20270112235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/headlines/*",
      "/*/headlines/*",
      "/community/*/post/*",
      "/community/*/live/*",
      "/community/*/topics/*",
      "/community/*/coins/*",
      "/community/*/profile/*",
      "/community/post/*",
      "/community/topics/*",
      "/community/coins/*",
      "/community/profile/*",
      "/dexscan/*"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-3-169-121-75.tpe53.r.cloudfront.net."
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
    "hsts": "max-age=31536000; includeSubdomains",
    "sitemap": {
      "urls": 27,
      "indexes": 28
    },
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
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
    "cdn": [
      "CloudFront",
      "Fastly"
    ]
  },
  "elapsed_s": 11.6,
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
