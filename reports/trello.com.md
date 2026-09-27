# Security Audit Report — trello.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://trello.com/ |
| Bug bounty program | Trello |
| Listed scope domain | trello.com |
| Test date | 2026-09-27 02:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **30** (High: 0, Medium: 0, Low: 5, Info: 25)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 19 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 20 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 21 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 22 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 23 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 24 | info | H23 | Edge advertises HTTP/3 (QUIC) via alt-svc | CWE-200 |
| 25 | info | H25 | server-timing response header exposed | CWE-200 |
| 26 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 27 | info | WK4 | RFC 8615 change-password endpoint live | CWE-200 |
| 28 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 29 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 30 | info | H12 | Proxy/edge hop chain disclosed via Via | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AtlassianEdge
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: AtlassianEdge
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.trello.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=L1Pv1rpciXhbLcwV1z84F6fdeNpGMIDd4nrgAzCQncc; google-site-verification=j10V2FxDCOpk-ZtvXbt0csUYbGo4uttk0VIeNN3pMwQ; atlassian-domain-verification=ZRphniOpyvhHV76mRmxnLkHJVrKnbeOIxmhbxb8PF6AarX0Fyp
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but trello.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 23 disallow path(s), e.g. /search?, /reset?, /confirm?, /confirmDelete?, ^/*/recommend
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://trello.com/ carries Cache-Control: max-age=0, s-maxage=604800, stale-if-error=604800, no-cache="Set-Cookie", must-revalidate; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.39 carries PTR server-54-192-248-39.tpe53.r.cloudfront.net. for trello.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on trello.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 19. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for trello.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 20. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on trello.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of trello.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 21. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of trello.com loads 3 cross-origin script(s) without an integrity attribute, e.g. https://atl-onetrust-wrapper.atlassian.com/assets/atl-onetrust-wrapper.min.js, https://trello-bifrost.prod-east.frontend.public.atl-paas.net/assets/trello-test-page.runtime.23f8aa95.js, https://trello-bifrost.prod-east.frontend.public.atl-paas.net/assets/trello-test-page.f0471f06.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 22. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on trello.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 23. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of trello.com references 5 distinct third-party registrable domains (e.g. orangelogic.com, ctfassets.net, atlassian.com, atl-paas.net, techvalidate.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 24. [INFO] Edge advertises HTTP/3 (QUIC) via alt-svc (`H23`)

- **CWE:** CWE-200
- **Detail:** The root response of trello.com carries alt-svc h3=":443"; ma=86400; QUIC/HTTP3 is enabled at the edge (protocol + port inventory).
- **Recommendation:** Confirm the QUIC port/endpoint is intended and monitored.

### 25. [INFO] server-timing response header exposed (`H25`)

- **CWE:** CWE-200
- **Detail:** The root response of trello.com sends server-timing (cdn-cache-hit,cdn-pop;desc="TPE53-P3",cdn-rid;desc="yXsSlHp4l6qouu_gskj4M22UKdNp); server/edge processing metrics are disclosed to any client.
- **Recommendation:** Restrict server-timing to authenticated/debug contexts if the internals are sensitive.

### 26. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on trello.com identify the edge as CloudFront / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 27. [INFO] RFC 8615 change-password endpoint live (`WK4`)

- **CWE:** CWE-200
- **Detail:** /.well-known/change-password on trello.com answers 200; a password-change service endpoint is advertised.
- **Recommendation:** Confirm the endpoint is an intended user-facing service.

### 28. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of trello.com contains wildcard SAN entry(ies) *.frontend.public.atl-paas.net, *.bitbucket.com, *.bitbucket.io; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 29. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of trello.com is http://ocsp.r2m01.amazontrust.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 30. [INFO] Proxy/edge hop chain disclosed via Via (`H12`)

- **CWE:** CWE-200
- **Detail:** The root of trello.com discloses a 1-hop fronting chain (1.1 a6cd9de66980942c2c8ead084584ba72.cloudfront.net (CloudFront)); the hop sequence inventories the intermediate edge/proxy layers in front of the origin.
- **Recommendation:** Confirm each hop is an intended layer; trim chain disclosure if unnecessary.

## Evidence (raw response observations)

```json
{
  "domain": "trello.com",
  "dns": {
    "a": [
      "54.192.248.39",
      "54.192.248.6",
      "54.192.248.49",
      "54.192.248.64"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-001d9801.gslb.pphosted.com (pref 10)",
      "mxb-001d9801.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-1442.awsdns-52.org.",
      "ns-2013.awsdns-59.co.uk.",
      "ns-722.awsdns-26.net.",
      "ns-402.awsdns-50.com."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=L1Pv1rpciXhbLcwV1z84F6fdeNpGMIDd4nrgAzCQncc",
      "google-site-verification=j10V2FxDCOpk-ZtvXbt0csUYbGo4uttk0VIeNN3pMwQ",
      "atlassian-domain-verification=ZRphniOpyvhHV76mRmxnLkHJVrKnbeOIxmhbxb8PF6AarX0FypthxYB/r5XpVC2E",
      "mailru-verification: 26cd15930108c82c",
      "google-site-verification=UqQbR3bkx0DW0mTjn4zpy-pFaTOtklFFLgVJPLpWBfg",
      "google-site-verification=m3SBLzut__3UbFT85xIcXyZs4CsOKfX6MrdByMh6xSM",
      "google-site-verification=klLlb7yZqSKsDzIEQ_Ck9G8vJZrZUYSl7G6SYm5ugaU",
      "google-site-verification=XiTuMrGYNDAcJ3h6FgJn-qK1wWhcRCTrwK7ihP4lgzQ",
      "v=spf1 include:_spf.google.com include:_spf.salesforce.com include:spemail.trello.com include:cust-spf.exacttarget.com include:amazonses.com -all",
      "google-site-verification=rSOg_zfvrFkmPwI-Yg4oLj8SNdFQnPCeo9a0GtDf_y4",
      "facebook-domain-verification=5g7n6qixu6oqonzuw4igcyn2fd52yi",
      "google-site-verification=lFRc2QYcvrD1x-JP-sbqyEHEVFTzLiYr_s5TMwqDPGE",
      "google-site-verification=dk_f7jMXJqZs_HAQ5Qvd1LMExtsW6rL0_3vK6wMWxyM",
      "slack-domain-verification=IQyaWt1Bt2nVwCvOsgj2ObAap344ynM5bV6C8zlZ"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=quarantine; adkim=r; aspf=r; fo=1; pct=100; rua=mailto:dmarc_rua@emaildefense.proofpoint.com,mailto:dmarc-rua@abuse.atlassian.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com,mailto:dmarc-ruf@abuse.atlassian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.frontend.public.atl-paas.net",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Jul 27 00:00:00 2026 GMT",
    "notAfter": "Feb  9 23:59:59 2027 GMT",
    "san": [
      "*.frontend.public.atl-paas.net",
      "bitbucket.org",
      "*.bitbucket.com",
      "*.bitbucket.io",
      "*.teamworkgraph.ai",
      "*.dataapps.shared.atlassian-3p.com",
      "*.devsphere.tools.atlassian.com",
      "*.rovo.com",
      "*.halp.com",
      "halp.com",
      "*.internal.atlassian.com",
      "atlassian.design",
      "*.atlassian.com",
      "*.prod-apse.frontend.public.atl-paas.net",
      "*.us-west-2.prod.public.atl-paas.net",
      "*.atl-paas.net",
      "*.prod.atlassian-dev.net",
      "*.sbox.shared.atlassian-3p.com",
      "bitbucket.io",
      "*.prod-east.frontend.public.atl-paas.net",
      "*.remix.prod.atlassian-dev.net",
      "*.atlassian.dev",
      "teamworkgraph.com",
      "*.prod-west.frontend.public.atl-paas.net",
      "teamworkgraph.ai",
      "atlassian.dev",
      "*.pipelines-remote-access.shared.atlassian-3p.com",
      "apkg.io",
      "*.trello.com",
      "trello.com",
      "*.atlassian-isolated-3p.com",
      "*.kaizen.shared.atlassian-3p.com",
      "atlassian-3p.com",
      "atlassian.com",
      "*.prod-west2.frontend.public.atl-paas.net",
      "*.prod-euwest.frontend.public.atl-paas.net",
      "*.teamworkgraph.com",
      "*.bytebucket.org",
      "*.prod.atl-paas.net",
      "*.prod-eucentral.frontend.public.atl-paas.net",
      "rovo.com",
      "jira.com",
      "*.prod-apse2.frontend.public.atl-paas.net",
      "bitbucket.com",
      "*.atlassian-3p.com",
      "*.us-east-1.prod.public.atl-paas.net",
      "*.bitbucket.org",
      "atlassian-isolated-3p.com",
      "*.status.atlassian.com",
      "*.apkg.io",
      "bytebucket.org",
      "*.jira.com",
      "puds.prod.atl-paas.net",
      "*.prod.public.atl-paas.net"
    ],
    "days_left": 135,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.39",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Capture, organize, and tackle your to-dos from anywhere"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: AtlassianEdge"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.trello.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://trello.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 200,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 200
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=L1Pv1rpciXhbLcwV1z84F6fdeNpGMIDd4nrgAzCQncc",
    "google-site-verification=j10V2FxDCOpk-ZtvXbt0csUYbGo4uttk0VIeNN3pMwQ",
    "atlassian-domain-verification=ZRphniOpyvhHV76mRmxnLkHJVrKnbeOIxmhbxb8PF6AarX0Fyp",
    "mailru-verification: 26cd15930108c82c",
    "google-site-verification=UqQbR3bkx0DW0mTjn4zpy-pFaTOtklFFLgVJPLpWBfg"
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
      "serial": 3284483683141803136198984546703460166,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "san": [
        "*.frontend.public.atl-paas.net",
        "bitbucket.org",
        "*.bitbucket.com",
        "*.bitbucket.io",
        "*.teamworkgraph.ai",
        "*.dataapps.shared.atlassian-3p.com",
        "*.devsphere.tools.atlassian.com",
        "*.rovo.com",
        "*.halp.com",
        "halp.com",
        "*.internal.atlassian.com",
        "atlassian.design",
        "*.atlassian.com",
        "*.prod-apse.frontend.public.atl-paas.net",
        "*.us-west-2.prod.public.atl-paas.net",
        "*.atl-paas.net",
        "*.prod.atlassian-dev.net",
        "*.sbox.shared.atlassian-3p.com",
        "bitbucket.io",
        "*.prod-east.frontend.public.atl-paas.net"
      ],
      "subject_dn": "3127302506035504030c1e2a2e66726f6e74656e642e7075626c69632e61746c2d706161732e6e6574",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20260727000000",
      "not_after": "20270209235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/search?",
      "/reset?",
      "/confirm?",
      "/confirmDelete?",
      "^/*/recommend",
      "*/add-card?",
      "*/login?",
      "*/signup?",
      "/forgot$",
      "/statement/",
      "/boardinvited/",
      "/invite/",
      "/organizationinvited/",
      "/boardInviteDeclined/",
      "/organizationInviteDeclined/"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-54-192-248-39.tpe53.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 200,
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
    "hsts": "max-age=63072000; preload",
    "security_txt": "/.well-known/security.txt",
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
    "server_timing": "cdn-cache-hit,cdn-pop;desc=\"TPE53-P3\",cdn-rid;desc=\"yXsSlHp4l6qouu_gskj4M22UKdNp-j4kGc0nYfgq3STnJI6iA3R74g==\",cdn-hit-la",
    "cdn": [
      "CloudFront",
      "Fastly"
    ],
    "change_password": true
  },
  "x17": {
    "wildcard_san": [
      "*.frontend.public.atl-paas.net",
      "*.bitbucket.com",
      "*.bitbucket.io",
      "*.teamworkgraph.ai",
      "*.dataapps.shared.atlassian-3p.com"
    ],
    "ocsp_http": "http://ocsp.r2m01.amazontrust.com",
    "via": "1.1 a6cd9de66980942c2c8ead084584ba72.cloudfront.net (CloudFront)"
  },
  "elapsed_s": 13.8,
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
