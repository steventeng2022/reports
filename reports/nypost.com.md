# Security Audit Report — nypost.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nypost.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nypost.com |
| Test date | 2026-09-27 02:39 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **27** (High: 0, Medium: 0, Low: 2, Info: 25)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P11 | WordPress login page exposed | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 15 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 16 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 17 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 18 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 19 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 20 | info | HTML4 | Meta generator tag discloses site technology | CWE-200 |
| 21 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 22 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 23 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 24 | info | HTML12 | preconnect/dns-prefetch declares third-party destinations | CWE-200 |
| 25 | info | HTML16 | Inline event handlers in root document | CWE-79 |
| 26 | info | HTML19 | data: URIs present in root document | CWE-200 |
| 27 | info | CT1 | 48 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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
- **Detail:** Detected: Server: nginx; X-Powered-By: WordPress VIP <https://wpvip.com>
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=uNoIhBXurxzVlQa0FvK2t9Yld5byfvXbFRQaMToGvrieKjBdyl; google-site-verification=pkTc123LIT1uBNNTg9WvGeJjxI0rCnCzmcVYSeFyLFU; apple-domain-verification=37Qe0gDvvRCGgED6VegwSRnviuX7KRbEhaVgN8IGXpQ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of nypost.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but nypost.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 168 disallow path(s), e.g. /wp-admin/, /wp-json/, /wp-login.php, /tag/credible/, /personal-finance/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://nypost.com/ carries Cache-Control: private, max-age=60; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 15. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk7fa4pb8gnr2m.html -> 404; error page/headers match: Nginx, WordPress.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 16. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on nypost.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 17. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for nypost.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 18. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on nypost.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of nypost.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 19. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of nypost.com loads 6 cross-origin script(s) without an integrity attribute, e.g. https://cdn.cookielaw.org/scripttemplates/otSDKStub.js, https://tagan.adlightning.com/nc-nypost/op.js, https://www.googletagmanager.com/gtag/js?id=G-0DZ7LHF5PZ; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 20. [INFO] Meta generator tag discloses site technology (`HTML4`)

- **CWE:** CWE-200
- **Detail:** Root document of nypost.com declares generator: WordPress 6.8.10; generator tags fingerprint the site builder/CMS for targeted attacks.
- **Recommendation:** Remove the generator meta tag or keep it consistent with the deployed version.

### 21. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of nypost.com references 20 distinct third-party registrable domains (e.g. typekit.net, gmpg.org, cookielaw.org, adlightning.com, gstatic.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 22. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of nypost.com sends a CSP but contains 32 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 23. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on nypost.com identify the edge as Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 24. [INFO] preconnect/dns-prefetch declares third-party destinations (`HTML12`)

- **CWE:** CWE-200
- **Detail:** Root document of nypost.com declares preconnect/dns-prefetch/modulepreload for 10 third-party registrable domain(s) (e.g. cookielaw.org, doubleclick.net, google.com); declared (not yet loaded) destinations widen the expected network topology of the page.
- **Recommendation:** Review declared third-party destinations as part of the supply-chain inventory.

### 25. [INFO] Inline event handlers in root document (`HTML16`)

- **CWE:** CWE-79
- **Detail:** The root document of nypost.com contains 28 inline event handler attribute(s); each is a DOM-level execution point that SRI does not constrain.
- **Recommendation:** Move handlers to external scripts where feasible and keep them covered by CSP.

### 26. [INFO] data: URIs present in root document (`HTML19`)

- **CWE:** CWE-200
- **Detail:** The root document of nypost.com references 1 data: URI payload(s); inline data resources bypass the normal fetch/CORS path and should be inventoried.
- **Recommendation:** Review inline data payloads (especially scripts/iframes) as part of the asset inventory.

### 27. [INFO] 48 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: careers.nypost.com, my.nypost.com, shop.nypost.com, store.nypost.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "nypost.com",
  "dns": {
    "a": [
      "192.0.66.32"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00596a01.gslb.pphosted.com (pref 10)",
      "mxb-00596a01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-670.awsdns-19.net.",
      "ns-1469.awsdns-55.org.",
      "ns-1696.awsdns-20.co.uk.",
      "ns-112.awsdns-14.com."
    ],
    "caa": [],
    "spf": [
      "atlassian-domain-verification=uNoIhBXurxzVlQa0FvK2t9Yld5byfvXbFRQaMToGvrieKjBdylMs8jcSXRKQKqao",
      "google-site-verification=pkTc123LIT1uBNNTg9WvGeJjxI0rCnCzmcVYSeFyLFU",
      "apple-domain-verification=37Qe0gDvvRCGgED6VegwSRnviuX7KRbEhaVgN8IGXpQ",
      "knowbe4-site-verification=0694ce74005828dc4bb8b7299bfb6f61",
      "64392d9425e042418ac52d053c1ecb2f",
      "onetrust-domain-verification=e7aaac6a2eba4af5831f665fd4355b18",
      "globalsign-domain-verification=E1A5DBF2B0DE3B53A5674C61CAB23AD2",
      "ZOOM_verify_59WiJX6USMK92Hbu6-iuEg",
      "google-site-verification=S57vRF8jMqWVb1wbslt1vZqTKLBQPRLeihUQGU4LQL4",
      "gc-ai-domain-verification-pqnv2r=6l7d3qRIy8sKfMz0EsSBxqr80",
      "google-site-verification=43S5hR4E09EYHuJ0EddR08WUtCjmPb3zJDOY1qaqieg",
      "globalsign-domain-verification=015A85DB506CC703E147E2E1A8234FFA",
      "google-site-verification=rqQNsAZmdVyYCBkD6XaUsf_6Aq8knJPcJ_AJm_15mSM",
      "openai-domain-verification=dv-zTDjYaeUtH0Z7a6WRNHJHPNH",
      "facebook-domain-verification=a5ak341y6mn6scu375wpuvy5h38u0",
      "profound-domain-verification-f8v9td=J1enbUIBGr8ls69bKh4sLheZC",
      "google-site-verification=Ut_6-La1_H3SIW8cw3Jxn5gBHjCOb1mEm5wEciI90j8",
      "pinterest-site-verification=8ee9ddd73c0b33e9c9606a95d1763cc7",
      "google-site-verification=PN2Qi9bdkJ4SDeGCzwK6mosjk_cdEPkd-epRWHrqs7M",
      "figma-domain-verification=b411f1d2852c2c7e057a2d6d70fb22896f37ccc1412d1e1bb4f9da14e2b78ad9-1769000244",
      "globalsign-domain-verification=14BE65E00D7267440AC2843EDFF82780",
      "ValidationTokenValue=be3a705a-0d8d-4c88-91dc-0ebe1d8e2f6d",
      "globalsign-domain-verification=DC5FAF3AEB5DC469953A669244E3DABD",
      "apple-domain-verification=lPyM98oF1jmNh7Ts",
      "tollbit-domain-verification=80476469dd961d48a2f36d45785f7b4bf6823867c0b612c475a6b073c762576c",
      "yahoo-verification-key=ZGc2aNHEalcpUmqoYUCKock6uR7n971BQPyq+avH5js=",
      "adobe-idp-site-verification=7ef638bb68822798685f96e436bfc87a6f79319dd86369e447b84bb8ea9c6f68",
      "ZOOM_verify_GgmxWj_4QZCCMGFMQbCp5Q",
      "google-site-verification=TfuBznU2bqij21_J2S6N2IDNQta9zajEFCIxJuh033J",
      "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDiTxvTgpRaUPa3Zsawin7pRP+CPIij6s1io0EsxRAfrCox6uw/QdKyEiozMHKz14AWPx6gLqb09Om7xmN9Snb5tcnWQdD46XFld1rm+DVwP1UezK/VagJDp6aMhabY1T1hBpK4R/YBnQ70R1AivL6Km7TfNgRU6UMSx2TtQnkFawIDAQAB",
      "amazonses:C+fSBo78zXZisXWUUbHRXRXY19xolN+ug+xevTtXL+k=",
      "amazonses:nZi4yMmejKgD3iT0h5S+LGrgaQGq6NVUPnD4v+R9htc=",
      "google-site-verification=5uYHzCPszHHLF2QyFiup1p177WJxzsWoUNaUCs_fhkQ",
      "v=spf1 ip4:205.203.130.22 ip4:205.203.130.101 ip4:205.203.130.102 ip4:205.203.136.101 ip4:205.203.136.102 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=quarantine; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=nypost.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Aug 11 00:41:43 2026 GMT",
    "notAfter": "Nov  9 00:41:42 2026 GMT",
    "san": [
      "nypost.com",
      "www.nypost.com"
    ],
    "days_left": 42,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.32",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "New York Post – Breaking News, Top Headlines, Photos & Videos"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: nginx",
    "X-Powered-By: WordPress VIP <https://wpvip.com>"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.nypost.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://nypost.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 48,
    "notable": [
      "careers.nypost.com",
      "my.nypost.com",
      "shop.nypost.com",
      "store.nypost.com"
    ],
    "sample": [
      "ads.nypost.com",
      "advertising.nypost.com",
      "ai-develop.nypost.com",
      "ai-preprod.nypost.com",
      "ai.nypost.com",
      "ascend.nypost.com",
      "bytes.nypost.com",
      "cancel.nypost.com",
      "careers.nypost.com",
      "chp.nypost.com",
      "embeds-develop.nypost.com",
      "embeds-preprod.nypost.com",
      "embeds-sandbox.nypost.com",
      "embeds.nypost.com",
      "events.nypost.com",
      "guide.nypost.com",
      "hamilton-benchmark.nypost.com",
      "hamilton-benchmark.stag.nypost.com",
      "links.nypost.com",
      "my.nypost.com"
    ]
  },
  "apex_txt": [
    "atlassian-domain-verification=uNoIhBXurxzVlQa0FvK2t9Yld5byfvXbFRQaMToGvrieKjBdyl",
    "google-site-verification=pkTc123LIT1uBNNTg9WvGeJjxI0rCnCzmcVYSeFyLFU",
    "apple-domain-verification=37Qe0gDvvRCGgED6VegwSRnviuX7KRbEhaVgN8IGXpQ",
    "knowbe4-site-verification=0694ce74005828dc4bb8b7299bfb6f61",
    "onetrust-domain-verification=e7aaac6a2eba4af5831f665fd4355b18"
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
      "aia_ocsp": null,
      "serial": 455627650958874930503890185474129909318671,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://ye2.c.lencr.org/16.crl"
      ],
      "san": [
        "nypost.com",
        "www.nypost.com"
      ],
      "subject_dn": "311330110603550403130a6e79706f73742e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594532",
      "not_before": "20260811004143",
      "not_after": "20261109004142"
    }
  },
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/wp-json/",
      "/wp-login.php",
      "/tag/credible/",
      "/personal-finance/",
      "/banking/",
      "/credit-cards/",
      "/loans/",
      "/personal-loans/",
      "/refinance-student-loans/",
      "/student-loans/",
      "/mortgages/",
      "/home-equity/",
      "/mortgage-rates/",
      "/mortgage-refinance/"
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
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://ye2.c.lencr.org/16.crl",
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
      "Fastly"
    ],
    "preconnect": [
      "cookielaw.org",
      "doubleclick.net",
      "google.com",
      "googleapis.com",
      "googlesyndication.com",
      "googletagservices.com",
      "gstatic.com",
      "typekit.net",
      "wordpress.com",
      "wp.com"
    ]
  },
  "x17": {
    "inline_handlers": 28,
    "data_uris": 1
  },
  "elapsed_s": 34.3,
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
